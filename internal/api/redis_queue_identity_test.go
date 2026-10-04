package api

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/redisqueue"
)

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestRedisProtocol_IdentityEnforced_RejectsRemoteClient(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-password")
	t.Setenv("CPA_MANAGEMENT_TAILSCALE_LOGIN", "operator@example.test")
	redisqueue.SetEnabled(false)
	t.Cleanup(func() { redisqueue.SetEnabled(false) })

	server := newTestServer(t)
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close() })
	remote := &net.TCPAddr{IP: net.ParseIP("100.96.113.54"), Port: 51515}
	done := make(chan struct{})
	go func() {
		server.handleRedisConnection(remoteAddrConn{Conn: serverSide, remote: remote}, nil)
		close(done)
	}()

	_ = clientSide.SetDeadline(time.Now().Add(2 * time.Second))
	go func() { _ = writeTestRESPCommand(clientSide, "AUTH", "test-management-password") }()
	if msg, err := readTestRESPError(bufio.NewReader(clientSide)); err != nil {
		t.Fatalf("failed to read rejection: %v", err)
	} else if msg != "ERR redis usage output is limited to local clients" {
		t.Fatalf("unexpected rejection: %q", msg)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected connection handler to return after rejection")
	}
}

func TestRedisProtocol_IdentityEnforced_AllowsLoopbackClient(t *testing.T) {
	const managementPassword = "test-management-password"
	t.Setenv("MANAGEMENT_PASSWORD", managementPassword)
	t.Setenv("CPA_MANAGEMENT_TAILSCALE_LOGIN", "operator@example.test")
	redisqueue.SetEnabled(false)
	t.Cleanup(func() { redisqueue.SetEnabled(false) })

	server := newTestServer(t)
	addr, stop := startRedisMuxListener(t, server)
	t.Cleanup(stop)

	conn, errDial := net.DialTimeout("tcp", addr, time.Second)
	if errDial != nil {
		t.Fatalf("failed to dial redis listener: %v", errDial)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if errWrite := writeTestRESPCommand(conn, "AUTH", managementPassword); errWrite != nil {
		t.Fatalf("failed to write AUTH command: %v", errWrite)
	}
	if msg, errRead := readTestRESPSimpleString(bufio.NewReader(conn)); errRead != nil {
		t.Fatalf("failed to read AUTH response: %v", errRead)
	} else if msg != "OK" {
		t.Fatalf("unexpected AUTH response: %q", msg)
	}
}
