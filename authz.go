package authz

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

type Session struct {
	id        string
	userID    string
	groupID   string
	expiresAt int64
	obsolete  bool
}

type SessionManager struct {
	keys           []string
	db             *sql.DB
	sessionTimeout int64
	tokenTimeout   int64
}

var (
	ErrDBService = errors.New("login-authz - database operation failed")
	ErrCryptoService = errors.New("login-authz - crypto operation failed")
	ErrSIDCookieSyntax    = errors.New("login-authz - sid cookie syntax - possible tampering")
	ErrSIDCookieSignature = errors.New("login-authz - sid cookie signature - possible tampering")
	ErrTokCookieSyntax    = errors.New("login-authz - tok cookie syntax - possible tampering")
	ErrTokCookieSignature = errors.New("login-authz - tok cookie signature - possible tampering")
	ErrCredentialReuse    = errors.New("login-authz - possible session fixation")
	ErrLeakedSecret       = errors.New("login-authz - possible leaked secret")
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

func (mgmt *SessionManager) UserID(r *http.Request, w http.ResponseWriter) (string, bool, error) {
	var uid string
	var ok bool
	var err1 error
	var err2 error
	uid, ok, err1 = mgmt.readTok(r, w)
	if !ok {
		uid, ok, err2 = mgmt.readSID(r, w)
	}
	return uid, ok, errors.Join(err1, err2)
}

func (mgmt *SessionManager) setTokCookie(uid string, w http.ResponseWriter) {
	tok := uid + "." + strconv.FormatInt(time.Now().Unix()+mgmt.tokenTimeout, 10)
	hash := hmac.New(sha256.New, []byte(mgmt.keys[0]))
	hash.Write([]byte(tok))
	mac := hash.Sum(nil)
	cookie := &http.Cookie{
		Name:     "__Host-tok",
		Value:    string(mac) + "." + tok,
		Path:     "/",
		MaxAge:   int(mgmt.tokenTimeout),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func (mgmt *SessionManager) setSIDCookie(sid string, w http.ResponseWriter) {
	hash := hmac.New(sha256.New, []byte(mgmt.keys[0]))
	hash.Write([]byte(sid))
	mac := hash.Sum(nil)
	cookie := &http.Cookie{
		Name:     "__Host-sid",
		Value:    string(mac) + "." + sid,
		Path:     "/",
		MaxAge:   int(mgmt.sessionTimeout),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func (mgmt *SessionManager) readTok(r *http.Request, w http.ResponseWriter) (string, bool, error) {
	cookie, err := r.Cookie("__Host-tok")
	if err != nil {
		return "", false, nil
	}
	tok := cookie.Value
	mac, tok, found := strings.Cut(tok, ".")
	if !found {
		http.SetCookie(w, dropTokCookie)
		return "", false, ErrTokCookieSyntax
	}
	var targetMAC []byte
	var match bool
	for i := 0; i < len(mgmt.keys); i++ {
		hash := hmac.New(sha256.New, []byte(mgmt.keys[i]))
		hash.Write([]byte(tok))
		targetMAC = hash.Sum(nil)
		match = hmac.Equal([]byte(mac), targetMAC)
		if match {
			break
		}
	}
	if !match {
		http.SetCookie(w, dropTokCookie)
		return "", false, ErrTokCookieSignature
	}
	uid, expiresAtStr, found := strings.Cut(tok, ".")
	if !found {
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

func (mgmt *SessionManager) readSID(r *http.Request, w http.ResponseWriter) (string, bool, error) {
	cookie, err := r.Cookie("__Host-sid")
	if err != nil {
		return "", false, nil
	}
	mac, id, found := strings.Cut(cookie.Value, ".")
	if !found {
		http.SetCookie(w, dropSIDCookie)
		return "", false, ErrSIDCookieSyntax
	}
	var targetMAC []byte
	var match bool
	for i := 0; i < len(mgmt.keys); i++ {
		hash := hmac.New(sha256.New, []byte(mgmt.keys[i]))
		hash.Write([]byte(id))
		targetMAC = hash.Sum(nil)
		match = hmac.Equal([]byte(mac), targetMAC)
		if match {
			break
		}
	}
	if !match {
		http.SetCookie(w, dropSIDCookie)
		return "", false, ErrSIDCookieSignature
	}
	sess := Session{}
	sess.id = id
	err = mgmt.db.QueryRow(`
	SELECT
		user_id,
		group_id,
		expires_at,
		obsolete
	FROM
		session WHERE id = ?`, id).Scan(
		&sess.userID,
		&sess.groupID,
		&sess.expiresAt,
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
		_, err := mgmt.db.Exec("DELETE FROM session WHERE user_id = ?", sess.userID)
		if err != nil {
			http.SetCookie(w, dropSIDCookie)
			return "", false, errors.Join(ErrCredentialReuse, ErrDBService, err)
		}
		http.SetCookie(w, dropSIDCookie)
		return "", false, ErrCredentialReuse
	}
	if time.Now().Unix() > sess.expiresAt {
		_, err := mgmt.db.Exec("DELETE FROM session WHERE group_id = ?", sess.groupID)
		if err != nil {
			http.SetCookie(w, dropSIDCookie)
			return "", false, errors.Join(ErrDBService, err)
		}
		http.SetCookie(w, dropSIDCookie)
		return "", false, nil
	}
	_, err = mgmt.db.Exec("UPDATE session SET obsolete = true WHERE id = ?", sess.id)
	if err != nil {
		http.SetCookie(w, dropSIDCookie)
		return "", false, errors.Join(ErrDBService, err)
	}
	newId := make([]byte, 16)
	_, err = rand.Read(newId)
	if err != nil {
		http.SetCookie(w, dropSIDCookie)
		return "", false, errors.Join(ErrCryptoService, err)
	}
	newSess := Session{
		hex.EncodeToString(newId),
		sess.userID,
		sess.groupID,
		sess.expiresAt,
		false,
	}
	_, err = mgmt.db.Exec(`
	INSERT INTO session (
		id,
		user_id
		group_id,
		expires_at,
		obsolete
	) VALUES (
		?,?,?,?,?
	)`,
		newSess.id,
		newSess.userID,
		newSess.groupID,
		newSess.expiresAt,
		newSess.obsolete,
	)
	if err != nil {
		http.SetCookie(w, dropSIDCookie)
		return "", false, errors.Join(ErrDBService, err)
	}
	mgmt.setTokCookie(newSess.userID, w)
	mgmt.setSIDCookie(newSess.id, w)
	return newSess.userID, true, nil
}

// API
// * UserID(r *http.Request, w http.ResponseWriter) (string, bool, error)
//
// * Enable(uid string) (error)
// create session
// set cookies
//
// If the db query fails, client cookies will still be removed.
// It is recommended to alert the user-agent if they intended to logout of all devices.
// * Disable(all bool) (error)
// if all { delete by userID } else { delete by groupID }
// remove cookies
