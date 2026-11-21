/*
 * Modified by Nexwall, 2026-10-04: new file, implements ADR 0001
 * (docs/adr/0001-sso-handoff-from-partner-program.md). Not derived from
 * any NethServer/nethsecurity-controller source -- new code, same
 * GPL-2.0-only license as the rest of this file's package.
 */

package middleware

import (
	"net/http"
	"sync"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/nexwall/nexwall-multitenant-sso/handoff"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/methods"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/response"
	"github.com/NethServer/nethsecurity-controller/api/storage"
)

// handoffSeenStore enforces single-use handoff tokens for the lifetime of
// this process. See the package doc in nexwall-multitenant-sso/handoff for
// why a shared (e.g. Redis-backed) SeenStore would be needed instead if
// this instance ever runs more than one replica -- it does not today (see
// ADR 0007 in nexwall-multi-tenant: Recreate strategy, single replica).
var handoffSeenStore = handoff.NewMemorySeenStore()
var handoffSeenStoreOnce sync.Once

// SSOHandoff implements POST /sso/handoff?token=... (ADR 0001). Accepts a
// token minted by nexwall-partner-multitenant, verifies it against this
// tenant's own SSO_HANDOFF_SECRET, and on success mints a normal session
// token via the same gin-jwt mechanism /login uses -- same output, a
// different, additional input. Does not replace local username/password
// login, which remains available unconditionally.
func SSOHandoff(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "missing token query parameter",
			Data:    nil,
		}))
		return
	}

	if configuration.Config.SSOHandoffSecret == "" {
		// Deliberately the same generic message as every other failure
		// path below: whether the feature is unconfigured, the token is
		// malformed, or the token is simply wrong, a caller holding an
		// invalid token learns nothing about which case it was.
		logs.Logs.Println("[WARN][SSO] handoff attempted but SSO_HANDOFF_SECRET is not configured for this tenant")
		c.JSON(http.StatusUnauthorized, structs.Map(response.StatusUnauthorized{
			Code:    401,
			Message: "invalid or expired token",
			Data:    nil,
		}))
		return
	}

	claims, err := handoff.Verify(
		[]byte(configuration.Config.SSOHandoffSecret),
		token,
		configuration.Config.FQDN,
		handoffSeenStore,
	)
	if err != nil {
		logs.Logs.Println("[WARN][SSO] handoff verify failed: " + err.Error())
		c.JSON(http.StatusUnauthorized, structs.Map(response.StatusUnauthorized{
			Code:    401,
			Message: "invalid or expired token",
			Data:    nil,
		}))
		return
	}

	username := claims.Subject

	// ADR 0011 (nexwall-multi-tenant): a token signed with the tenant's own secret
	// and carrying an explicit role ("admin" or "user") is the control plane
	// vouching for a verified identity (Logto sign-in with MFA), so the local
	// account is created on first use and its admin flag follows the role.
	// Firewall groups stay managed inside the controller. A token without a role
	// keeps the original behavior: the account must already exist.
	if admin, ok := ssoRole(claims.Role); ok {
		created, err := storage.EnsureSSOAccount(username, ssoDisplayName(username), admin)
		if err != nil {
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Code:    500,
				Message: "could not prepare the account",
				Data:    nil,
			}))
			return
		}
		if created {
			logs.Logs.Println("[INFO][SSO] account created from handoff for " + username)
		}
	} else if storage.GetPassword(username) == "" {
		logs.Logs.Println("[WARN][SSO] handoff for unknown local user " + username)
		c.JSON(http.StatusUnauthorized, structs.Map(response.StatusUnauthorized{
			Code:    401,
			Message: "invalid or expired token",
			Data:    nil,
		}))
		return
	}

	jwtMiddleware := InstanceJWT()
	tokenString, expire, err := jwtMiddleware.TokenGenerator(&models.UserAuthorizations{
		Username: username,
	})
	if err != nil {
		logs.Logs.Println("[ERR][SSO] token generation failed for " + username + ": " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "could not create session",
			Data:    nil,
		}))
		return
	}

	// Mirror LoginResponse's own behavior exactly (middleware/middleware.go):
	// a 2FA-enabled user's token is minted but not yet marked valid, so it
	// still requires the normal 2FA step before it can authorize a request.
	// SSO does not bypass 2FA.
	parsedToken, _ := jwtMiddleware.ParseTokenString(tokenString)
	tokenClaims := jwt.ExtractClaimsFromToken(parsedToken)
	if tfa, ok := tokenClaims["2fa"].(bool); !ok || !tfa {
		methods.SetTokenValidation(username, tokenString)
	}

	logs.Logs.Println("[INFO][SSO] handoff success for user " + username)
	c.JSON(http.StatusOK, gin.H{"code": 200, "expire": expire, "token": tokenString})
}

// ssoRole maps the handoff role claim to the controller administrator flag.
// Any other value (including empty) is not a provisioning role.
func ssoRole(role string) (admin bool, ok bool) {
	switch role {
	case "admin":
		return true, true
	case "user":
		return false, true
	}
	return false, false
}

// ssoDisplayName is the part of the e-mail before the @.
func ssoDisplayName(username string) string {
	for i := 0; i < len(username); i++ {
		if username[i] == '@' {
			if i == 0 {
				break
			}
			return username[:i]
		}
	}
	return username
}
