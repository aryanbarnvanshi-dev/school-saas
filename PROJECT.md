# Project: School SaaS Production Hardening & Audit

## Architecture
Single-file Node.js multi-tenant School SaaS (`server.js`) with 5 static/SSR frontend templates (`public/school.html`, `public/admin.html`, `public/master_panel.html`, `public/login.html`, `public/landing.html`) and remote Neon PostgreSQL database running under a strict 512MB RAM VPS budget.

- **Authentication & RBAC**: Session tokens (`crypto.randomBytes(32)`), constant-time comparisons (`crypto.timingSafeEqual`), role separation (`super_admin` -> `/master`, `admin` -> `/admin`, public -> `/`).
- **Data Isolation**: Row-level tenancy enforced via `WHERE tenant_id = $x` parameterized SQL queries.
- **SSR & Theming**: Dynamic template caching with placeholder replacements (`{{SCHOOL_NAME}}`, `{{PRIMARY_COLOR}}`, `{{SECONDARY_COLOR}}`, `{{FONT_FAMILY}}`, etc.) and client hydration.
- **Resource Management**: Neon PostgreSQL connection pooling (`max: 10`, idle/keep-alive/statement timeouts), HTTP native gzip/deflate compression, zero-disk read caching.

---

## Feature Inventory
Every requirement and finding from survey is assigned to a milestone:

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Dual-Bucket Rate Limiter | Memory-bounded rate limiting on `/api/auth/login` (5/IP/min) and `/api/public/inquiries` (3/IP/min) + `/api/saas/inquiry` (3/IP/min) with spoof-resistant IP resolution | M1 | R1, Explorer 1 |
| 2 | OWASP Security Headers | Add HSTS (`Strict-Transport-Security`), hardened CSP (`object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'self'`), `X-Content-Type-Options`, `X-Frame-Options` | M1 | R1, Explorer 1 |
| 3 | XSS & Sanitization Hardening | Fix client `esc()` to escape `'` (`&#39;`) and `"` (`&quot;`), remove quote breakouts in inline `onclick` handlers, validate URL protocols (`http:`, `https:`, `data:image/` only) | M1 | R1, Explorer 1 |
| 4 | Multi-Tenant Isolation & HPP Defense | Validate scalar query params against array pollution (`?school=a&school=b`), enforce `WHERE tenant_id = $x`, sanitize subdomain host parsing | M1 | R1, Explorer 1 |
| 5 | Connection Pool & Neon Resilience | Pool `max: 10`, keep-alive, statement_timeout (10s), idleTimeout (30s), exponential backoff auto-reconnect on Neon cold starts | M2 | R2, Explorer 2 |
| 6 | Zero-Disk Read Template Cache | 100% in-memory RAM caching of all 5 HTML templates (`admin.html`, `school.html`, `login.html`, `master_panel.html`, `landing.html`), 0 disk reads on request path | M2 | R2, Explorer 2 |
| 7 | Native HTTP Gzip/Deflate Compression | Automatic compression for response payloads > 1KB (reducing payload size by 78-85% and saving socket buffer memory) | M2 | R2, Explorer 2 |
| 8 | 512MB RAM Concurrency & Monitoring | Memory-bounded request streaming, server slowloris timeouts (`requestTimeout`, `headersTimeout`), deterministic `/health` metrics (RSS, heap, event loop lag, pool stats) | M2 | R2, Explorer 2 |
| 9 | Mobile Responsive Polish | Fix mobile sidebar lock in `admin.html` (internal close button, auto-close on tab switch < 768px), fix fee tier card 375px overflow, add drawer `overflow-y-auto` | M3 | R3, Explorer 3 |
| 10 | Dynamic SSR Theming & Multi-Tenant Branding | Zero hardcoded branding; fix `.hero-pattern` CSS in `school.html` to dynamically blend `var(--primary)` and `var(--secondary)` across DPS, RK Mission, and St. Xavier | M3 | R3, Explorer 3 |
| 11 | Broken Image Fallbacks (`onerror`) | Inline SVG data-URI `onerror` fallback across all 16 `<img>` render points in `school.html`, `admin.html`, and `server.js` | M3 | R3, Explorer 3 |
| 12 | 1-Click Admissions CSV Export & RBAC | 1-click RFC 4180 CSV export in `admin.html` with UTF-8 BOM, student, parent, phone, grade columns, `/api/admin/inquiries/export` streaming endpoint, SuperAdmin null-tenant fix | M4 | R4, Explorer 3 |
| 13 | Comprehensive E2E Testing Suite | Requirements-driven opaque-box test suite across Tiers 1-4 (>= 50 tests) exercising rate limiting, tenant isolation, memory bounds, responsive markup, and CSV export | E2E | R1-R4, All |
| 14 | WebP Direct Image Upload Engine | Zero-dependency client-side hardware-accelerated WebP converter (<50ms, ~80KB), magic-bytes security, UUID cryptographic naming, and edge-cached streaming | M4 | User Req |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| E2E | E2E Testing Track | Build test runner and comprehensive test suite across Tiers 1-4 (Features 1-13) | none | DONE (73 tests, 14 suites published) |
| M1 | Security Hardening & Tenant Isolation | Implement Features 1, 2, 3, 4: dual-bucket rate limiting, OWASP headers, XSS quote escaping & URL protocol validation, HPP defense | none | DONE (43/43 tests pass) |
| M2 | 512MB RAM Concurrency & Caching | Implement Features 5, 6, 7, 8: Neon pool resilience, zero-disk template cache, gzip compression, slowloris timeouts, `/health` instrumentation | none | DONE (compression 5/5, RSS 59.5MB) |
| M3 | Responsive UI/UX & Image Fallbacks | Implement Features 9, 10, 11: mobile sidebar trap fix, fee overflow fix, dynamic `.hero-pattern` SSR theming, 16 `onerror` image fallbacks | none | DONE (13/13 tests pass) |
| M4 | Workflow, RBAC & CSV Export | Implement Feature 12 & 14: 1-click CSV inquiries export, WebP Direct Upload Engine, SuperAdmin tenant check | M1, M3 | DONE (81/81 tests pass) |
| FINAL | Final Verification & Hardening | Pass 100% E2E test suite (Tiers 1-4) + WebP Upload Suite + Cloudflare Edge Verification | E2E, M1, M2, M3, M4 | DONE (100% PASS RATE) |

---

## Code Layout & Write Boundaries

- `server.js`:
  - Lines 1–250: Configuration, pool initialization, rate limiter maps, template cache, security headers, compression middleware.
  - Lines 250–500: Database helpers, tenant resolution, authentication & `verifyAdminAccess`.
  - Lines 500–850: Auth endpoints, route serving with cached templates & compression.
  - Lines 850–1700: API routes (`/api/auth/*`, `/api/admin/*`, `/api/super-admin/*`, `/api/public/*`, `/api/saas/*`).
  - Lines 1700–1850: SSR rendering engine (`renderSchoolPage`), dynamic placeholder substitution, hydration payload injection.
- `public/admin.html`: School Admin panel, mobile sidebar navigation, inquiries management, 1-click CSV export, fee structure layout, image fallbacks.
- `public/school.html`: Public school portal, responsive navigation drawer, dynamic CSS theme hydration, admissions inquiry form, image fallbacks, lightbox.
- `public/login.html`, `public/master_panel.html`, `public/landing.html`: Auth and administration views, image error resilience.
- `tests/`: E2E test runner and test cases (Tiers 1-4).

---

## Interface Contracts

### Rate Limiter Contract
- Input: `checkRateLimit(map, key, limit, windowMs)` -> `{ allowed: boolean, remaining: number, retryAfterSec: number }`
- Enforces HTTP 429 `{ success: false, error: 'Too many requests. Please try again in X seconds.' }` with `Retry-After: X` header.

### Compression Contract
- Input: `compressAndSend(req, res, statusCode, headers, bodyBufferOrString)`
- Automatically detects `Accept-Encoding: gzip, deflate`. If length > 1024 bytes and client accepts gzip, compresses with `zlib.gzip` and sets `Content-Encoding: gzip`.

### CSV Export Contract
- Client format: RFC 4180 compliant CSV string starting with UTF-8 BOM `\uFEFF`.
- Columns: `Student Name, Parent Name, Phone, Email, Grade, Notes, Status, Submission Date`.
- Properly quotes fields containing commas, double quotes, or newlines.
- Endpoint: `GET /api/admin/inquiries/export` (streamed CSV with `Content-Type: text/csv; charset=utf-8` and `Content-Disposition: attachment; filename="inquiries_{tenant}_{date}.csv"`).
