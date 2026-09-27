package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestManagementIdentityGate(t *testing.T) {
	for _, tc := range []struct {
		name, path, peer, login, protocol string
		want                              int
	}{
		{"approved TLS proxy", "/v0/management/config", "127.0.0.1:1234", "owner@example.test", "https", 204},
		{"approved IPv6 proxy", "/management.html", "[::1]:1234", "owner@example.test", "https", 204},
		{"direct tailnet cannot spoof headers", "/v0/management/config", "100.64.0.2:1234", "owner@example.test", "https", 403},
		{"other identity", "/v0/management/auth-files/download", "127.0.0.1:1234", "other@example.test", "https", 403},
		{"missing identity", "/management.html", "127.0.0.1:1234", "", "https", 403},
		{"HTTP rejected", "/management.html", "127.0.0.1:1234", "owner@example.test", "http", 403},
		{"forwarded address does not grant access", "/v0/management/config", "192.0.2.1:1234", "owner@example.test", "https", 403},
		{"inference unchanged", "/v1/responses", "100.64.0.2:1234", "", "", 204},
		{"models unchanged", "/v1/models", "100.64.0.2:1234", "", "", 204},
		{"messages unchanged", "/v1/messages", "100.64.0.2:1234", "", "", 204},
		{"direct plugin resource rejected", "/v0/resource/plugins/test", "100.64.0.2:1234", "owner@example.test", "https", 403},
		{"approved plugin resource", "/v0/resource/plugins/test", "127.0.0.1:1234", "owner@example.test", "https", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(managementIdentityMiddleware("owner@example.test"))
			router.Any(tc.path, func(c *gin.Context) { c.Status(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("Tailscale-User-Login", tc.login)
			req.Header.Set("X-Forwarded-Proto", tc.protocol)
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
		})
	}
}

func TestManagementIdentityGateRejectsDuplicateHeaders(t *testing.T) {
	for _, header := range []string{"Tailscale-User-Login", "X-Forwarded-Proto"} {
		t.Run(header, func(t *testing.T) {
			router := gin.New()
			router.Use(managementIdentityMiddleware("owner@example.test"))
			router.GET("/management.html", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodGet, "/management.html", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Tailscale-User-Login", "owner@example.test")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Add(header, req.Header.Get(header))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", response.Code)
			}
		})
	}
}

func TestManagementIdentityGateDisabledWithoutConfiguration(t *testing.T) {
	router := gin.New()
	router.Use(managementIdentityMiddleware(""))
	router.GET("/management.html", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/management.html", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}
