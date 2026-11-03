# E2E Test Suite Infrastructure & Architecture

## Overview
The School SaaS E2E Test Suite provides comprehensive, opaque-box, requirement-driven verification for the multi-tenant single-file Node.js platform (`server.js`) and its frontend views (`public/*.html`). It strictly verifies acceptance criteria R1 through R4 from `ORIGINAL_REQUEST.md` and architecture milestones from `PROJECT.md`.

- **Test Suite Engine**: Native Node.js CommonJS test runner (`tests/run_tests.js`) — zero external test framework dependencies required.
- **Protocol**: Opaque-box HTTP/REST testing over live sockets with decompressed body inspection, cryptographic session management, and PostgreSQL fixture verification.
- **Coverage**: 14 test suites, 73 total automated test cases spanning 4 rigorous tiers.

---

## 4-Tier Test Suite Structure

```
tests/
├── run_tests.js                               # Unified CLI test runner
├── helpers/
│   ├── test_client.js                         # Opaque-box HTTP client with gzip, headers, auth
│   ├── db_helper.js                           # Neon PostgreSQL fixtures and test account provisioning
│   └── assertions.js                          # Invariant assertions and error reporting
├── tier1_features/
│   ├── test_rate_limiting.js                  # 6 tests: Login 429, reset on success, public inquiry limiter, OTP cooldown/lockout
│   ├── test_security_headers.js               # 6 tests: HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer/Permissions
│   ├── test_tenant_isolation.js               # 6 tests: 401 unauth, cross-tenant inquiries 403, cross-tenant update 403, notices 403, settings 403, data isolation
│   ├── test_compression.js                    # 5 tests: Gzip on >1KB payload, identity/no-compression, <1KB small payload, decompressed fidelity, landing page compression
│   ├── test_ssr_theming.js                    # 5 tests: DPS Delhi branding, RK Mission branding, St. Xavier branding, 404 unknown slug, root landing page
│   ├── test_image_fallbacks.js                # 5 tests: SSR logo onerror, toppers onerror, facilities onerror, gallery/lightbox onerror, admin previews onerror
│   └── test_csv_export.js                     # 5 tests: Endpoint 200, text/csv content-type, UTF-8 BOM (\uFEFF), RFC 4180 columns, tenant isolation
├── tier2_boundaries/
│   ├── test_brute_force_lockouts.js           # 5 tests: 5th attempt threshold, 6th attempt active lock, case-insensitivity, empty password 400, >128 chars 400
│   ├── test_header_spoofing_xff.js            # 5 tests: Rotating XFF rate limit enforcement, multi-hop parsing, malformed XFF injection, IPv6 support, Host spoofing 404
│   ├── test_xss_sanitization.js               # 5 tests: Script tag input rejection (400), attribute breakout, admin esc() quote escaping, school esc() quote escaping, server escapeForHtml
│   ├── test_hpp_pollution.js                  # 5 tests: ?school=a&b array handling, ?tenant_id array, pagination defaults, prototype pollution safety, empty query param
│   └── test_broken_image_urls.js              # 5 tests: javascript: scheme rejection (400), malformed file:/// schemes, >2000 char URLs, CSP img-src directives, SSR robustness
├── tier3_cross_feature/
│   └── test_cross_feature.js                  # 6 tests: Admin access while IP rate limited, cross-tenant IDOR quarantine, CSV export during concurrent writes, password spraying, Unicode inquiry lifecycle, session logout invalidation
└── tier4_workloads/
    └── test_real_world_workloads.js           # 4 tests: Full admissions lead journey, multi-tenant SSR concurrent hydration, SuperAdmin oversight vs School Admin RBAC, concurrency stress & memory RSS budget (<250MB peak load)
```

---

## Authoritative Test Output & Requirement Mapping

| Tier | Suite | Tests | Requirement Source | Key Verifications |
|------|-------|-------|-------------------|-------------------|
| **Tier 1** | `test_rate_limiting.js` | 6 | R1, Feature 1 | Login lockout after 5 failures, counter reset on success, inquiry spam protection (3-5/IP/min), OTP cooldown (60s) & lockout |
| **Tier 1** | `test_security_headers.js` | 6 | R1, Feature 2 | HSTS (`Strict-Transport-Security: max-age=...`), `nosniff`, `SAMEORIGIN`, `Content-Security-Policy` directives, `Cache-Control: no-store` |
| **Tier 1** | `test_tenant_isolation.js` | 6 | R1, Feature 4 | 401 unauth, 403 cross-tenant inquiry reading, 403 cross-tenant update, 403 notice injection, 403 settings tamper, tenant data scoping |
| **Tier 1** | `test_compression.js` | 5 | R2, Feature 7 | HTTP gzip compression on payloads >1024 bytes, identity non-compression, <1KB bypass, verbatim decompressed content parity, >50% compression ratio |
| **Tier 1** | `test_ssr_theming.js` | 5 | R3, Feature 10 | Dynamic SSR placeholder substitution, DPS branding, RK Mission branding, St. Xavier branding, 404 on unmapped slug, marketing landing |
| **Tier 1** | `test_image_fallbacks.js` | 5 | R3, Feature 11 | Presence of inline SVG data-URI or `onerror` fallback handlers on all image render points across SSR and client views |
| **Tier 1** | `test_csv_export.js` | 5 | R4, Feature 12 | `GET /api/admin/inquiries/export` streaming endpoint, `text/csv`, UTF-8 BOM (`\uFEFF`), RFC 4180 headers, strict tenant isolation |
| **Tier 2** | `test_brute_force_lockouts.js` | 5 | R1, Feature 1 | Exact 5th attempt lock boundary, 6th attempt lockout persistence, case-insensitive identifier tracking, empty password, >128 char limit |
| **Tier 2** | `test_header_spoofing_xff.js` | 5 | R1, Feature 1, 4 | Client rotating X-Forwarded-For headers cannot evade rate limiting, multi-hop parsing, SQL/control char safety, IPv6 parsing, Host header isolation |
| **Tier 2** | `test_xss_sanitization.js` | 5 | R1, Feature 3 | Raw script tag rejection (HTTP 400), attribute breakout neutralization, client `esc()` escaping of `'` (`&#39;`) and `"` (`&quot;`), server `escapeForHtml` |
| **Tier 2** | `test_hpp_pollution.js` | 5 | R1, Feature 4 | Duplicate query parameters (`?school=a&b`), duplicate `?tenant_id`, pagination array pollution, `__proto__` pollution immunity, empty parameters |
| **Tier 2** | `test_broken_image_urls.js` | 5 | R1, R3, Feature 3, 11 | `javascript:` URL protocol rejection (HTTP 400), `file:///` rejection, >2000 char URLs, CSP `img-src` data-URI and CDN whitelist |
| **Tier 3** | `test_cross_feature.js` | 6 | R1-R4, Features 1, 4, 12 | Admin CMS immunity from public inquiry IP limits, cross-tenant IDOR quarantine, CSV export under concurrent write load, password spraying defense, Unicode lead lifecycle, logout session invalidation |
| **Tier 4** | `test_real_world_workloads.js` | 4 | R1-R4, Features 1-13 | Full admissions lifecycle (capture -> DB -> admin status update -> CSV export -> cross-tenant verification), concurrent 3-tenant SSR rendering, SuperAdmin vs SchoolAdmin RBAC, concurrency load & memory RSS budget (<250MB peak load) |

---

## How to Run Tests

Ensure the server is running on port 3000 (`node server.js`).

### Run All 73 Tests Across Tiers 1-4
```powershell
node tests/run_tests.js
```

### Run by Specific Tier
```powershell
node tests/run_tests.js --tier=1       # Run Tier 1 Feature Coverage (38 tests)
node tests/run_tests.js --tier=2       # Run Tier 2 Boundary Cases (25 tests)
node tests/run_tests.js --tier=3       # Run Tier 3 Cross-Feature Combinations (6 tests)
node tests/run_tests.js --tier=4       # Run Tier 4 Real-World Workload Scenarios (4 tests)
```

### Run a Specific Test Suite File
```powershell
node tests/run_tests.js tests/tier1_features/test_security_headers.js
node tests/run_tests.js tests/tier1_features/test_tenant_isolation.js
node tests/run_tests.js tests/tier1_features/test_rate_limiting.js
node tests/run_tests.js tests/tier2_boundaries/test_xss_sanitization.js
node tests/run_tests.js tests/tier4_workloads/test_real_world_workloads.js
```

### Run with Pattern Matching Filter
```powershell
node tests/run_tests.js --grep=lockout
node tests/run_tests.js --grep=isolation
node tests/run_tests.js --grep=export
```
