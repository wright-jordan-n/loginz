package session

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
	userId    string
	groupId   string
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
	ErrInternalService = errors.New("")
	ErrSidCookieTamper = errors.New("")
	ErrTokCookieTamper = errors.New("")
	ErrCredentialReuse = errors.New("")
	ErrNoActiveSession = errors.New("")
	ErrNoActiveToken   = errors.New("")
	ErrLeakedSecret    = errors.New("")
)

func (mgmt *SessionManager) User(r *http.Request, w http.ResponseWriter) (string, error) {
	var uid string
	var err1 error
	var err2 error
	uid, err1 = mgmt.readTok(r)
	if err1 != nil {
		uid, err2 = mgmt.readSid(r, w)
	}
	return uid, errors.Join(err1, err2)
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

func (mgmt *SessionManager) setSidCookie(sid string, w http.ResponseWriter) {
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

func (mgmt *SessionManager) readTok(r *http.Request) (string, error) {
	cookie, err := r.Cookie("tok")
	if err != nil {
		return "", ErrNoActiveToken
	}
	tok := cookie.Value
	mac, tok, found := strings.Cut(tok, ".")
	if !found {
		return "", ErrTokCookieTamper
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
		return "", ErrTokCookieTamper
	}
	uid, expiresAtStr, found := strings.Cut(tok, ".")
	if !found {
		return "", ErrLeakedSecret
	}
	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil {
		return "", ErrLeakedSecret
	}
	if time.Now().Unix() > expiresAt {
		return "", ErrNoActiveToken
	}
	return uid, nil
}

func (mgmt *SessionManager) readSid(r *http.Request, w http.ResponseWriter) (string, error) {
	cookie, err := r.Cookie("sid")
	if err != nil {
		return "", ErrNoActiveSession
	}
	mac, id, found := strings.Cut(cookie.Value, ".")
	if !found {
		return "", ErrSidCookieTamper
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
		return "", ErrSidCookieTamper
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
		&sess.userId,
		&sess.groupId,
		&sess.expiresAt,
		&sess.obsolete,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNoActiveSession
		}
		return "", errors.Join(ErrInternalService, err)
	}
	if sess.obsolete {
		_, err := mgmt.db.Exec("DELETE FROM session WHERE group_id = ?", sess.groupId)
		if err != nil {
			return "", errors.Join(ErrCredentialReuse, ErrInternalService, err)
		}
		return "", ErrCredentialReuse
	}
	if time.Now().Unix() > sess.expiresAt {
		_, err := mgmt.db.Exec("DELETE FROM session WHERE group_id = ?", sess.groupId)
		if err != nil {
			return "", errors.Join(ErrNoActiveSession, ErrInternalService, err)
		}
		return "", ErrNoActiveSession
	}
	newId := make([]byte, 16)
	_, err = rand.Read(newId)
	if err != nil {
		return "", errors.Join(ErrInternalService, err)
	}
	sess.obsolete = true
	newSess := Session{
		hex.EncodeToString(newId),
		sess.userId,
		sess.groupId,
		sess.expiresAt,
		false,
	}
	ch1 := make(chan error)
	go func() {
		var err error
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
			newSess.userId,
			newSess.groupId,
			newSess.expiresAt,
			newSess.obsolete,
		)
		ch1 <- err
	}()
	ch2 := make(chan error)
	go func() {
		var err error
		_, err = mgmt.db.Exec(`
			UPDATE session
			SET obsolete = true
			WHERE id = ?
		`, sess.id)
		ch2 <- err
	}()
	err1 := <-ch1
	err2 := <-ch2
	if err1 != nil || err2 != nil {
		return "", errors.Join(ErrInternalService, err1, err2)
	}
	mgmt.setTokCookie(newSess.userId, w)
	mgmt.setSidCookie(newSess.id, w)
	return newSess.userId, nil
}

// API
// * User(r *http.Request, w http.ResponseWriter) string
//
// * Enable(uid string)
// create initial session
// set both cookies
//
// * Disable(all bool)
// if all { delete group } else { obsolete individual }
// remove cookies
