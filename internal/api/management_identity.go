package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// managementIdentityMiddleware adds an identity check to management routes only.
// allowedLogins is a comma-separated list of approved Tailscale logins.
// The loopback listener must be reached through Tailscale Serve, which replaces
// client-supplied identity headers. Local processes remain inside the trust boundary.
func managementIdentityMiddleware(allowedLogins string) gin.HandlerFunc {
	allowed := make(map[string]struct{})
	for _, login := range strings.Split(allowedLogins, ",") {
		if login = strings.TrimSpace(login); login != "" {
			allowed[login] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		management := path == "/management.html" || path == "/v0/management" ||
			strings.HasPrefix(path, "/v0/management/") || path == "/v8/management" ||
			strings.HasPrefix(path, "/v8/management/") || strings.HasPrefix(path, "/v0/resource/plugins/")
		if !management || len(allowed) == 0 {
			c.Next()
			return
		}

		c.Header("Cache-Control", "no-store")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		peer := net.ParseIP(host)
		logins := c.Request.Header.Values("Tailscale-User-Login")
		protocols := c.Request.Header.Values("X-Forwarded-Proto")
		approved := len(logins) == 1
		if approved {
			_, approved = allowed[logins[0]]
		}
		if err != nil || peer == nil || !peer.IsLoopback() || !approved ||
			len(protocols) != 1 || protocols[0] != "https" {
			log.WithField("event", "management_access_denied").Warn("management identity check failed")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "management requires the approved Tailscale identity over HTTPS"})
			return
		}
		c.Next()
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions {
			log.WithFields(log.Fields{
				"event": "management_operation", "identity": logins[0],
				"method": c.Request.Method, "route": c.FullPath(), "status": c.Writer.Status(),
			}).Info("management request completed")
		}
	}
}
