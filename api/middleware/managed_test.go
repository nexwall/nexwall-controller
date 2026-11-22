package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/gin-gonic/gin"
)

func managedRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/accounts", BlockWhenManaged(), func(c *gin.Context) { c.Status(http.StatusCreated) })
	r.DELETE("/accounts/:id", BlockWhenManaged(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	return r
}

func TestBlockWhenManaged(t *testing.T) {
	prev := configuration.Config.IdentityManaged
	t.Cleanup(func() { configuration.Config.IdentityManaged = prev })
	r := managedRouter()

	configuration.Config.IdentityManaged = false
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/accounts", nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("standalone mode must keep creating accounts, got %d", w.Code)
	}

	configuration.Config.IdentityManaged = true
	for _, tc := range []struct{ method, path string }{{http.MethodPost, "/accounts"}, {http.MethodDelete, "/accounts/7"}} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s: managed mode must answer 403, got %d", tc.method, tc.path, w.Code)
		}
		if body := w.Body.String(); !contains(body, "managed_identity") {
			t.Fatalf("%s %s: body must name the reason, got %s", tc.method, tc.path, body)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
