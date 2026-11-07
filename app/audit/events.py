class UserEvents:
    CREATED = "user.created"
    LOGIN_SUCCESS = "user.login.success"
    LOGIN_FAILURE = "user.login.failure"
    LOGOUT = "user.logout"
    DISABLED = "user.disabled"
    PASSWORD_CHANGED = "password.changed"

class ClientEvents:
    CREATED = "client.created"

class OAuthEvents:
    AUTHORIZE_SUCCESS = "oauth.authorize.success"
    AUTHORIZE_FAILURE = "oauth.authorize.failure"
    TOKEN_ISSUED = "token.issued"
    TOKEN_REFRESHED = "token.refreshed"
    TOKEN_REUSE_DETECTED = "token.reuse_detected"
    TOKEN_REVOKED = "token.revoked"
    AUTH_CODE_REUSE_DETECTED = "auth_code.reuse_detected"
    CLIENT_CREATED = "client.created"
    CLIENT_SECRET_ROTATED = "client.secret_rotated"
    CLIENT_ENABLED = "client.enabled"
    CLIENT_DISABLED = "client.disabled"
    SESSION_REVOKED = "session.revoked"