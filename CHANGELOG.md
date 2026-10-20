# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scripts/check_aws.py preflight|verify`: read-only checks for the AWS deployment. Preflight finds resources left from an earlier stack, a missing ECS cluster, certificate and allowlist mismatches and an unpushed `lde_image`. Verify checks services, targets, DNS, secret shape (never values) and the live endpoints.

### Security

- `POST /api/extract-packages {url}` now checks every hop of a fetch before connecting: a redirect to a private, loopback, link-local, multicast, shared-range (100.64.0.0/10) or non-80/443 target is refused before any request reaches it, and the connection is made to the address that passed the check, so a DNS-rebinding name cannot pass the check with one answer and connect with another. Before this, only the first URL was checked before the request, a redirect target was fetched first and checked after, and 100.64.0.0/10 passed. A response body is capped at 8 MB.
- `basic_auth_credentials` in `.settings.json` (or `LDE_BASIC_AUTH_CREDENTIALS`) now activates the login gate locally, as the docs said. The loader dropped the key, so a local server configured with a password still served without one.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 (`pbkdf2_sha256$600000$<salt>$<hash>`, `backend/passwords.py`) by `scripts/set_lde_password.py`. The unsalted `sha256` hex of earlier secrets still verifies, with one warning per user in the server log and a WARN from `check_aws.py verify`. A verified password is remembered in memory for five minutes, keyed by the stored hash; failed attempts are never cached.
- A negative or non-numeric `Content-Length` is a 400. `rfile.read(-1)` previously blocked the handler thread until the client closed the connection.
- `GET /api/runs/{id}/logs/{org}/{repo}` validates the org and repo like the other per-repo endpoints and refuses a path that resolves outside the run's directory.
- `PUT /api/settings` rejects a `gemini_model` with characters outside `[A-Za-z0-9._-]`, a `dtrack_url`/`dtrack_ui_url` that is not an http(s) URL, and a `default_orgs` that is not a list of organization names. The model name is also URL-quoted in the Gemini request path.
- The "Not found" and error cards in the SPA HTML-escape the path and message they show.
- Basic Auth compares the password hash in constant time (`hmac.compare_digest`), and a malformed stored hash returns 401 instead of raising.
- Behind the ALB (`X-Forwarded-Proto: https`), responses send `Strict-Transport-Security: max-age=63072000; includeSubDomains`. Plain-HTTP local runs don't.
- Finished background tasks that are never polled are dropped after 15 minutes, freeing their stored payloads.
- `POST` and `PUT` now require `Content-Type: application/json`, and are refused when an `Origin` header names a site other than localhost or `LDE_ALLOWED_ORIGIN`. Before this, any web page could drive a local LDE with a cross-site form or `fetch` request: start ingests, or run Gemini extractions on the configured key.
- One package extraction is limited to 20 Gemini calls (3,000 non-blank lines) and 170 seconds, and a failed chunk cancels the rest. A crafted 500 KB upload could previously trigger thousands of calls.
- The web server served any file under the app directory to a logged-in user, not just the UI. On AWS that included the data volume (`/data/depexplorer.db`, `/data/runs/...`) and every source file. It now serves only `index.html`, `css/` and `js/`, and returns 404 for everything else.

### Fixed

- The dev auto-reloader ignores dot-files. Saving Settings rewrote `.settings.json`, which restarted the server and killed every in-flight run and background extraction.
- `POST /api/extract-packages` returns 400 instead of 500 when `url` is not a string.
- `secrets_loader` signs with an aware UTC timestamp (`datetime.utcnow()` is deprecated in Python 3.12).
- `POST /api/runs` with only `org/repo` entries no longer fails with "No orgs provided" when `default_orgs` is empty, as on a fresh AWS deploy.
- Port 80 on the ALB redirects to HTTPS when the certificates come from `listener_certificate_arns`. It returned 404 unless `route53_zone_id` was set.

### Changed

- Ingest Dependencies no longer shows a method menu. New UI runs always use GitHub's Dependency Graph (`github_sbom`). ORT ingest is deprecated in the UI; it previously used the ORT connector to crunch SBOMs locally in Docker.
- Package Search hides the fallback-prompt textarea until **Copy fallback prompt** fails (clipboard unavailable). The native **Choose File** control is hidden; **Upload file** remains the only file picker.

## [0.1.0] - 2026-07-12

### Added

- Initial public release.
- **GitHub SBOM ingest** (default): converts GitHub's Dependency Graph
  (SPDX 2.3) to CycloneDX 1.4 and ingests into OWASP Dependency-Track — no
  repository cloning required.
- **ORT ingest** (local, Docker-based): resolves full transitive dependency
  graphs via the OSS Review Toolkit for repositories without the GitHub
  Dependency Graph enabled.
- **Package Search**: find which repositories contain a given npm/PyPI
  package, with deep links into Dependency-Track. Optional Gemini-based
  extraction of package names from an advisory URL or uploaded file.
- **Branch selection**: analyze a non-default branch per repository, with
  branch discovery across an org.
- Vanilla-JS single-page frontend (no build step) served by a stdlib-only
  Python HTTP server.
- Reference AWS ECS Fargate deployment (Terraform) and local `docker-compose`
  stack (Dependency-Track + optional caching proxies).
- Unit test suite (`pytest`) and opt-in end-to-end tests.

[Unreleased]: https://example.com/your-org/library-dependency-explorer/compare/v0.1.0...HEAD
[0.1.0]: https://example.com/your-org/library-dependency-explorer/releases/tag/v0.1.0
