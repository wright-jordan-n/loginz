**Do not use this library for anything important. It has not been thoroughly tested.**

# loginz

loginz is a login authorization library.

## Example

```
// %arg1 - signing keys (newest to oldest)
// %arg2 - An *sql.DB for SQLite3
// %arg3 - session timeout
// %arg4 - idle timeout
// %arg5 - token timeout
authz := loginz.NewAuthZManager([]string{"key1", "key2"}, db, 60*60*24*365, 60*60*24*14, 60*60)

http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	// Authentication is not part of this library.
	// It's expected that userID has a len of 32.
	// You should hex-encode 16 cryptographically random bytes.
	userID := authenticate()
	err := authz.Enable(userID, w)
	if err != nil {
		// Login failed.
		// Log errs.
	}
})

http.HandleFunc("/user", func(w http.ResponesWriter, r *http.Request) {
	userID, authorized, err := authz.UserID(r, w)
 if err != nil {
			// Log errs.
	}
	if !authorized {
		// User is not currently authorized.
	}
	fmt.Println(userID)
})

http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
	authorized, err := authz.Disable(true, r, w)
	if !authorized {
		// User is not currently authorized.
		// Cookies will be removed, but it's not guaranteed that db has been modified.
		// If the user wished to logout of all sessions (i.e. if the first arg is true), then they should be notified of failure to do so.
		if err != nil {
			// Failure to verify authorization was caused by an unexpected situation, rather than simply an absent or expired session.
			// Log errs.
		}
	}
})
```

## Summary

After a user is authenticated,
`func (authz *sessionManager) Enable(uid string, w http.ResponseWriter) error`
is called to initiate a new session. An access token is stored in the `tok`
cookie and a session ID is stored in the `sid` cookie.

For subsequent requests that require login authorization,
`func (authz *sessionManager) UserID(r *http.Request, w http.ResponseWriter) (string, bool, error)`
is used to obtain the user identifier.

To revoke authorization (aka logout),
`func (authz *sessionManager) Disable(all bool, r *http.Request, w http.ResponseWriter) (bool, error)`
is called. Where the `all` argument indicates whether to logout all user
sessions or only the current session.
