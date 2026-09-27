# Controlled releases

This branch starts at upstream v7.3.13. Production releases are built through
`matop/cliproxyapi-release-control`, which pins this source commit, a UI commit,
the Go toolchain, and the catalogs recorded in `catalog-lock.json`.

The upstream workflows are disabled in this fork's GitHub Actions settings.
Do not enable its upstream release or Docker publishing workflows. They use
upstream destinations and refresh model catalogs from a moving branch.

Run the controlled binary with `--local-model` and set
`remote-management.disable-auto-update-panel: true`. With this setting, a
missing management page returns 404. There is no fallback website download.
When updates are explicitly enabled, downloaded UI assets require SHA-256
metadata and matching bytes.

The optional `CPA_MANAGEMENT_TAILSCALE_LOGIN` environment variable adds an
identity restriction to the management page, management API, and plugin
management resources. It requires the configured login from Tailscale Serve
over HTTPS through a loopback connection. The management API still requires
its management key. Inference routes keep their existing API-key checks.

Only Tailscale Serve and trusted local processes may reach the loopback trust
boundary. Do not place another untrusted proxy in front of the same listener.
Direct remote requests cannot grant themselves access with forwarded headers.
This check does not establish whether the identity provider enforces MFA.

The dependency upgrades address findings from govulncheck. They do not establish
that every upstream vulnerability has been found. Run the release checks for
each approved source change.
