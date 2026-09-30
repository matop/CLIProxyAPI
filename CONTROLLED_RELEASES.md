# Controlled releases

This branch starts at upstream v8.0.4. Production releases are built through
`matop/cliproxyapi-release-control`, which pins this source commit, a UI commit,
the Go toolchain, and the catalogs recorded in `catalog-lock.json`.

`models.json` adds one entry to catalog commit `60e09976`: `claude-sonnet-5-5`
from router-for-me/models pull request 70. The `models.json` hash in
`catalog-lock.json` covers that entry. Drop the local entry when the upstream
catalog includes it.

The upstream workflows are disabled in this fork's GitHub Actions settings.
Do not enable its upstream release or Docker publishing workflows. They use
upstream destinations and refresh model catalogs from a moving branch.

Run the controlled binary with `--local-model` and set
`management.disable-auto-update-panel: true`. With this setting, a
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

The GPT-6.1 Sol entries come from router-for-me/models commit
`690c37fdbe62dc05f609f3a3e609d07ea4d16bf1`. This release adds the model to
Codex Plus, Team, and Pro, and to the Codex client model list. It preserves the
other pinned catalog entries. The catalog hashes record the exact combined
files.
