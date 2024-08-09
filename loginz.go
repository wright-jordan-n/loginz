package loginz

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type session struct {
	id           string
	userID       string
	groupID      string
	expiresAt    int64
	idleDeadline int64
	obsolete     bool
}

type sessionManager struct {
	keys           []string
	db             *sql.DB
	sessionTimeout int64
	idleTimeout    int64
	tokenTimeout   int64
}

func NewAuthZManager(
	keys []string,
	db *sql.DB,
	sessionTimeout int64,
	idleTimeout int64,
	tokenTimeout int64,
) *sessionManager {
	return &sessionManager{keys, db, sessionTimeout, idleTimeout, tokenTimeout}
}

var (
	ErrDBService          = errors.New("loginz - database operation failed")
	ErrCryptoService      = errors.New("loginz - crypto operation failed")
	ErrSIDCookieSyntax    = errors.New("loginz - sid cookie syntax - possible tampering")
	ErrSIDCookieSignature = errors.New("loginz - sid cookie signature - possible tampering")
	ErrTokCookieSyntax    = errors.New("loginz - tok cookie syntax - possible tampering")
	ErrTokCookieSignature = errors.New("loginz - tok cookie signature - possible tampering")
	ErrCredentialReuse    = errors.New("loginz - possible session fixation")
	ErrLeakedSecret       = errors.New("loginz - possible leaked secret")
)

var (
	dropTokCookie = &http.Cookie{
		Name:     "__Host-tok",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	dropSIDCookie = &http.Cookie{
		Name:     "__Host-sid",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
)

func (authz *sessionManager) Enable(uid string, w http.ResponseWriter) error {
	sessID := make([]byte, 16)
	_, err := rand.Read(sessID)
	if err != nil {
		return errors.Join(ErrCryptoService, err)
	}
	groupID := make([]byte, 16)
	_, err = rand.Read(groupID)
	if err != nil {
		return errors.Join(ErrCryptoService, err)
	}
	now := time.Now().Unix()
	sess := session{
		hex.EncodeToString(sessID),
		uid,
		hex.EncodeToString(groupID),
		now + authz.sessionTimeout,
		now + authz.idleTimeout,
		false,
	}
	_, err = authz.db.Exec(`
	INSERT INTO session (
		id,
		user_id,
		group_id,
		expires_at,
		idle_deadline,
		obsolete
	) VALUES (
		?,?,?,?,?,?
	)`,
		sess.id,
		sess.userID,
		sess.groupID,
		sess.expiresAt,
		sess.idleDeadline,
		sess.obsolete,
	)
	if err != nil {
		return errors.Join(ErrDBService, err)
	}
	authz.setTokCookie(sess.userID, w)
	authz.setSIDCookie(sess.id, w)
	return nil
}

func (authz *sessionManager) UserID(r *http.Request, w http.ResponseWriter) (string, bool, error) {
	var uid string
	var ok bool
	var err1 error
	var err2 error
	uid, ok, err1 = authz.readTok(r, w)
	if !ok {
		uid, ok, err2 = authz.readSID(r, w)
	}
	return uid, ok, errors.Join(err1, err2)
}

func (authz *sessionManager) Disable(all bool, r *http.Request, w http.ResponseWriter) (bool, error) {
	cookie, err := r.Cookie("__Host-sid")
	if err != nil {
		http.SetCookie(w, dropTokCookie)
		return false, nil
	}
	mac, id, found := strings.Cut(cookie.Value, ".")
	if !found || len(id) != 32 || len(mac) != 64 {
		http.SetCookie(w, dropTokCookie)
		http.SetCookie(w, dropSIDCookie)
		return false, ErrSIDCookieSyntax
	}
	var targetMAC []byte
	var match bool
	for i := 0; i < len(authz.keys); i++ {
		hash := hmac.New(sha256.New, []byte(authz.keys[i]))
		hash.Write([]byte(id))
		targetMAC = hash.Sum(nil)
		buf := []byte(mac)
		actual := make([]byte, hex.DecodedLen(len(buf)))
		_, err := hex.Decode(actual, buf)
		if err != nil {
			http.SetCookie(w, dropTokCookie)
			http.SetCookie(w, dropSIDCookie)
			return false, ErrSIDCookieSyntax
		}
		match = hmac.Equal(actual, targetMAC)
		if match {
			break
		}
	}
	if !match {
		http.SetCookie(w, dropTokCookie)
		http.SetCookie(w, dropSIDCookie)
		return false, ErrSIDCookieSignature
	}
	sess := session{id: id}
	err = authz.db.QueryRow(`
	SELECT
		user_id,
		group_id,
		expires_at,
		idle_deadline,
		obsolete
	FROM
		session WHERE id = ?`, sess.id).Scan(
		&sess.userID,
		&sess.groupID,
		&sess.expiresAt,
		&sess.idleDeadline,
		&sess.obsolete,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.SetCookie(w, dropTokCookie)
			http.SetCookie(w, dropSIDCookie)
			return false, nil
		}
		http.SetCookie(w, dropTokCookie)
		http.SetCookie(w, dropSIDCookie)
		return false, errors.Join(ErrDBService, err)
	}
	if sess.obsolete {
		_, err := authz.db.Exec("DELETE FROM session WHERE group_id = ?", sess.userID)
		if err != nil {
			http.SetCookie(w, dropTokCookie)
			http.SetCookie(w, dropSIDCookie)
			return false, errors.Join(ErrCredentialReuse, ErrDBService, err)
		}
		http.SetCookie(w, dropTokCookie)
		http.SetCookie(w, dropSIDCookie)
		return false, ErrCredentialReuse
	}
	now := time.Now().Unix()
	if now > sess.expiresAt || now > sess.idleDeadline {
		_, err := authz.db.Exec("DELETE FROM session WHERE group_id = ?", sess.groupID)
		if err != nil {
			http.SetCookie(w, dropTokCookie)
			http.SetCookie(w, dropSIDCookie)
			return false, errors.Join(ErrDBService, err)
		}
		http.SetCookie(w, dropTokCookie)
		http.SetCookie(w, dropSIDCookie)
		return false, nil
	}
	if all {
		_, err := authz.db.Exec("DELETE FROM session WHERE user_id = ?", sess.userID)
		if err != nil {
			http.SetCookie(w, dropTokCookie)
			http.SetCookie(w, dropSIDCookie)
			return false, errors.Join(ErrDBService, err)
		}
		http.SetCookie(w, dropTokCookie)
		http.SetCookie(w, dropSIDCookie)
		return true, nil
	} else {
		_, err := authz.db.Exec("DELETE FROM session WHERE group_id = ?", sess.groupID)
		if err != nil {
			http.SetCookie(w, dropTokCookie)
			http.SetCookie(w, dropSIDCookie)
			return false, errors.Join(ErrDBService, err)
		}
		http.SetCookie(w, dropTokCookie)
		http.SetCookie(w, dropSIDCookie)
		return true, nil
	}
}

func (authz *sessionManager) setTokCookie(uid string, w http.ResponseWriter) {
	tok := uid + "." + strconv.FormatInt(time.Now().Unix()+authz.tokenTimeout, 10)
	hash := hmac.New(sha256.New, []byte(authz.keys[0]))
	hash.Write([]byte(tok))
	mac := hash.Sum(nil)
	cookie := &http.Cookie{
		Name:     "__Host-tok",
		Value:    hex.EncodeToString(mac) + "." + tok,
		Path:     "/",
		MaxAge:   int(authz.tokenTimeout),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func (authz *sessionManager) setSIDCookie(sid string, w http.ResponseWriter) {
	hash := hmac.New(sha256.New, []byte(authz.keys[0]))
	hash.Write([]byte(sid))
	mac := hash.Sum(nil)
	cookie := &http.Cookie{
		Name:     "__Host-sid",
		Value:    hex.EncodeToString(mac) + "." + sid,
		Path:     "/",
		MaxAge:   int(authz.sessionTimeout),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func (authz *sessionManager) readTok(r *http.Request, w http.ResponseWriter) (string, bool, error) {
	cookie, err := r.Cookie("__Host-tok")
	if err != nil {
		return "", false, nil
	}
	tok := cookie.Value
	mac, tok, found := strings.Cut(tok, ".")
	if !found || len(mac) < 64 || len(tok) < 32 {
		http.SetCookie(w, dropTokCookie)
		return "", false, ErrTokCookieSyntax
	}
	var targetMAC []byte
	var match bool
	for i := 0; i < len(authz.keys); i++ {
		hash := hmac.New(sha256.New, []byte(authz.keys[i]))
		hash.Write([]byte(tok))
		targetMAC = hash.Sum(nil)
		buf := []byte(mac)
		actual := make([]byte, hex.DecodedLen(len(buf)))
		_, err := hex.Decode(actual, buf)
		if err != nil {
			http.SetCookie(w, dropTokCookie)
			return "", false, ErrTokCookieSyntax
		}
		match = hmac.Equal(actual, targetMAC)
		if match {
			break
		}
	}
	if !match {
		http.SetCookie(w, dropTokCookie)
		return "", false, ErrTokCookieSignature
	}
	uid, expiresAtStr, found := strings.Cut(tok, ".")
	if !found || len(uid) != 32 {
		http.SetCookie(w, dropTokCookie)
		return "", false, ErrLeakedSecret
	}
	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil {
		http.SetCookie(w, dropTokCookie)
		return "", false, ErrLeakedSecret
	}
	if time.Now().Unix() > expiresAt {
		http.SetCookie(w, dropTokCookie)
		return "", false, nil
	}
	return uid, true, nil
}

func (authz *sessionManager) readSID(r *http.Request, w http.ResponseWriter) (string, bool, error) {
	cookie, err := r.Cookie("__Host-sid")
	if err != nil {
		return "", false, nil
	}
	mac, id, found := strings.Cut(cookie.Value, ".")
	if !found || len(mac) != 64 || len(id) != 32 {
		http.SetCookie(w, dropSIDCookie)
		return "", false, ErrSIDCookieSyntax
	}
	var targetMAC []byte
	var match bool
	for i := 0; i < len(authz.keys); i++ {
		hash := hmac.New(sha256.New, []byte(authz.keys[i]))
		hash.Write([]byte(id))
		targetMAC = hash.Sum(nil)
		buf := []byte(mac)
		actual := make([]byte, hex.DecodedLen(len(buf)))
		_, err := hex.Decode(actual, buf)
		if err != nil {
			http.SetCookie(w, dropSIDCookie)
			return "", false, ErrSIDCookieSyntax
		}
		match = hmac.Equal(actual, targetMAC)
		if match {
			break
		}
	}
	if !match {
		http.SetCookie(w, dropSIDCookie)
		return "", false, ErrSIDCookieSignature
	}
	sess := session{id: id}
	err = authz.db.QueryRow(`
	SELECT
		user_id,
		group_id,
		expires_at,
		idle_deadline,
		obsolete
	FROM
		session WHERE id = ?`, sess.id).Scan(
		&sess.userID,
		&sess.groupID,
		&sess.expiresAt,
		&sess.idleDeadline,
		&sess.obsolete,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.SetCookie(w, dropSIDCookie)
			return "", false, nil
		}
		http.SetCookie(w, dropSIDCookie)
		return "", false, errors.Join(ErrDBService, err)
	}
	if sess.obsolete {
		_, err := authz.db.Exec("DELETE FROM session WHERE group_id = ?", sess.userID)
		if err != nil {
			http.SetCookie(w, dropSIDCookie)
			return "", false, errors.Join(ErrCredentialReuse, ErrDBService, err)
		}
		http.SetCookie(w, dropSIDCookie)
		return "", false, ErrCredentialReuse
	}
	now := time.Now().Unix()
	if now > sess.expiresAt || now > sess.idleDeadline {
		_, err := authz.db.Exec("DELETE FROM session WHERE group_id = ?", sess.groupID)
		if err != nil {
			http.SetCookie(w, dropSIDCookie)
			return "", false, errors.Join(ErrDBService, err)
		}
		http.SetCookie(w, dropSIDCookie)
		return "", false, nil
	}
	_, err = authz.db.Exec("UPDATE session SET obsolete = true WHERE id = ?", sess.id)
	if err != nil {
		http.SetCookie(w, dropSIDCookie)
		return "", false, errors.Join(ErrDBService, err)
	}
	newID := make([]byte, 16)
	_, err = rand.Read(newID)
	if err != nil {
		http.SetCookie(w, dropSIDCookie)
		return "", false, errors.Join(ErrCryptoService, err)
	}
	newSess := session{
		hex.EncodeToString(newID),
		sess.userID,
		sess.groupID,
		sess.expiresAt,
		now + authz.idleTimeout,
		false,
	}
	_, err = authz.db.Exec(`
	INSERT INTO session (
		id,
		user_id,
		group_id,
		expires_at,
		idle_deadline,
		obsolete
	) VALUES (
		?,?,?,?,?,?
	)`,
		newSess.id,
		newSess.userID,
		newSess.groupID,
		newSess.expiresAt,
		newSess.idleDeadline,
		newSess.obsolete,
	)
	if err != nil {
		http.SetCookie(w, dropSIDCookie)
		return "", false, errors.Join(ErrDBService, err)
	}
	authz.setTokCookie(newSess.userID, w)
	authz.setSIDCookie(newSess.id, w)
	return newSess.userID, true, nil
}
