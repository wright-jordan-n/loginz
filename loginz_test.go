package loginz

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/tursodatabase/go-libsql"
)

func TestEnable(t *testing.T) {
	file, err := os.CreateTemp("", "*.db")
	if err != nil {
		panic(err.Error())
	}
	defer os.Remove(file.Name())
	db, err := sql.Open("libsql", "file://"+file.Name())
	if err != nil {
		panic(err.Error())
	}
	_, err = db.Exec(`CREATE TABLE session (
		id data_type PRIMARY KEY,
		user_id data_type TEXT NOT NULL,
		group_id data_type TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		idle_deadline INTEGER NOT NULL,
		obsolete INTEGER NOT NULL
	) WITHOUT ROWID`)
	if err != nil {
		panic(err.Error())
	}

	buf := make([]byte, 16)
	_, err = rand.Read(buf)
	if err != nil {
		panic(err.Error())
	}
	uid := hex.EncodeToString(buf)
	// server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	authz := NewAuthZManager([]string{"key1", "key2"}, db, 60*60*24*365, 60*60*24*14, 60*60)
	// 	err := authz.Enable(uid, w)
	// 	if err != nil {
	// 		panic(err.Error())
	// 	}
	// }))
	// defer server.Close()
	// client := server.Client()
	// client.Get("/")
	authz := NewAuthZManager([]string{"key1", "key2"}, db, 60*60*24*365, 60*60*24*14, 60*60)
	enableHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := authz.Enable(uid, w)
		if err != nil {
			panic(err.Error())
		}
	})

	userIDHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok, err := authz.UserID(r, w)
		fmt.Println(uid, ok, err)
	})

	enableRes := httptest.NewRecorder()
	enableReq := httptest.NewRequest("GET", "/", nil)
	enableHandler(enableRes, enableReq)
	res := enableRes.Result()
	defer res.Body.Close()
	cookies := res.Cookies()
	fmt.Println(cookies)
	var (
		id            string
		user_id       string
		group_id      string
		expires_at    int64
		idle_deadline int64
		obsolete      bool
	)
	rows, err := db.Query("SELECT * FROM session")
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&id, &user_id, &group_id, &expires_at, &idle_deadline, &obsolete)
		if err != nil {
			panic(err.Error())
		}
		fmt.Println(id, user_id, group_id, expires_at, idle_deadline, obsolete)
	}
	err = rows.Err()
	if err != nil {
		panic(err.Error())
	}

	userIDRes := httptest.NewRecorder()
	userIDReq := httptest.NewRequest("GET", "/", nil)
	// for _, cookie := range enableRes.Result().Cookies() {
	// 	userIDReq.AddCookie(cookie)
	// }
	userIDReq.AddCookie(enableRes.Result().Cookies()[1])
	userIDHandler(userIDRes, userIDReq)
}
