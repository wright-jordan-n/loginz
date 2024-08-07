# loginz
loginz is a "defaults-only" login authorization library.

## Overview

After a user is authenticated, `func (authz *SessionManager) Enable(uid string, w http.ResponseWriter) error` is called to initiate a new session. An access token is stored in the `tok` cookie, and a session id is stored in the `sid` cookie.

For subsequent requests that require login authorization, `func (authz *SessionManager) UserID(r *http.Request, w http.ResponseWriter) (string, bool, error)` is used to obtain the user identifier.

In order to revoke authorization (aka logout), `func (authz *SessionManager) Disable(all bool, r *http.Request, w http.ResponseWriter) (bool, error)` is called. Where the `all` argument indicates whether to logout all user sessions or only the current session only.

### Philosophy

This library uses hybrid approach to session management. It combines the use of stateless access tokens with stateful session objects. The goal is to balance security and performance concerns.

### Automatic Session ID Renewal

This mechanism mirrors that of OAuth's Refresh Token Rotation. The session id may be thought of as a refresh token. Whenever a new access token is requested, the session id is used to generate it. The session object is then marked as obsolete, and is superseded by an associated session object with a new id. Session objects are associated by their initial authorization grant, so that if an obsolete session id used, then all session ids associated with the same grant are invalidated.

It should be noted that this mechanism can result in a race condition between a legitimate user and an attacker. The first entity to obtain an access token before the session id's reuse is detected will be free to use the provided access token until it expires. Keep this in mind when deciding on timeout values.

In the worst case scenario, if the legitimate user does not request any new access tokens, an attacker will be allowed to continually obtain new access tokens until the `idleTimeout` or `sessionTimeout` is enforced. 

### Timeouts

This library utilizes 3 different timeouts:

* tokenTimeout

The token timeout is the shortest of the 3 timeouts and controls the duration that an access token remains valid. This value has a correlated trade-off between performance and security. A lower timeout means less time that an attacker can potentially retain authorization in the event that session id reuse is detected. A higher timeout means less trips to the database to obtain new tokens.

* idleTimeout

The idle timeout indicates the amount of time that a session is allowed to remain valid without a request for a new access token.

* sessionTimeout

The session timeout is the longest timeout and is the maximum time that a session remains valid, regardless of activity.

### Use At Your Own Risk

Always verify and audit the implementation and use of third-party libraries such as this one.