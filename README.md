# Fuzzi Backend

Intelligent Web Misconfiguration Detection System — Django REST API backed by Supabase.

Fuzzi evaluates web application configurations using a **fuzzy rule-based inference engine** to produce graded, explainable risk scores. It helps administrators, security analysts, and developers identify misconfigurations, prioritise fixes, and track security posture over time.

---

## Stack

- Python 3.12 + Django 6 + Django REST Framework
- Supabase (PostgreSQL database, Auth, Storage)
- ReportLab (PDF generation)
- Deployed on Vercel (serverless)

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/fluxaro/fuzzi-backend.git
cd fuzzi-backend
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Fill in your Supabase keys and DATABASE_URL

# 3. Run schema in Supabase SQL Editor
#    Paste contents of supabase_schema.sql and run

# 4. Apply Django migrations
python manage.py migrate

# 5. Start server
python manage.py runserver
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `DJANGO_SECRET_KEY` | Django secret key |
| `DEBUG` | `True` for local, `False` for production |
| `ALLOWED_HOSTS` | Comma-separated allowed hosts |
| `DATABASE_URL` | Supabase PostgreSQL connection string (URL-encoded) |
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key (bypasses RLS) |
| `SUPABASE_ANON_KEY` | Anon/public key |
| `SUPABASE_JWT_SECRET` | JWT signing secret for token verification |
| `CORS_ALLOWED_ORIGINS` | Comma-separated frontend origins |

---

## Fuzzy Logic Engine

The core engine (`scanner/fuzzy_engine.py`) implements a **Mamdani-style Fuzzy Inference System** with:

- **14 input dimensions**: `security_headers`, `authentication_config`, `access_control`, `directory_permissions`, `error_handling`, `debug_mode`, `cloud_config`, `ssl_tls_config`, `input_validation`, `third_party_risk`, `seo_score`, `readability_score`, `design_consistency`, `performance_risk`
- **5-level linguistic variables**: VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH
- **40 predefined IF-THEN rules** covering OWASP/NIST best practices
- **Membership functions**: Triangular, Trapezoidal, Gaussian
- **Centroid defuzzification** → crisp risk score 0–1
- **Outputs**: `risk_score`, `risk_level`, `overall_score` (0–100), `category_scores`, `triggered_rules`, `explainability`

---

## API Endpoints

Base URL: `https://fuzzi-backend.vercel.app/api`

All endpoints except `/signup` and `/login` require:
```
Authorization: Bearer <supabase_access_token>
```

---

### Authentication

#### `POST /api/signup`
Create a new user account.

**Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "full_name": "Jane Doe",
  "role": "analyst"
}
```
**Response `201`:**
```json
{ "message": "User created successfully", "user_id": "uuid", "email": "user@example.com" }
```

---

#### `POST /api/login`
Authenticate and receive JWT tokens.

**Body:**
```json
{ "email": "user@example.com", "password": "SecurePass123!" }
```
**Response `200`:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": { "id": "uuid", "email": "...", "full_name": "...", "role": "analyst" }
}
```

---

#### `POST /api/logout`
Invalidate the current session.

**Response `200`:** `{ "message": "Logged out successfully" }`

---

#### `POST /api/password/change`
Change the authenticated user's password.

**Body:** `{ "new_password": "NewPass456!" }`

---

### Profile & Preferences

#### `GET /api/me`
Get the current user's profile including preferences.

**Response `200`:**
```json
{
  "id": "uuid", "email": "...", "full_name": "...", "role": "analyst",
  "organization": "...", "total_scans": 12, "alert_threshold": 0.7,
  "preferences": { "theme": "dark", "email_alerts": true, ... }
}
```

---

#### `PUT /api/profile`
Update profile fields (`full_name`, `organization`, `avatar_url`, `alert_threshold`).

---

#### `GET /api/preferences`
Get notification and dashboard preferences.

#### `POST /api/preferences`
Update preferences.

**Body:**
```json
{
  "theme": "dark",
  "email_alerts": true,
  "alert_on_critical": true,
  "notifications_enabled": true,
  "webhook_url": "https://hooks.slack.com/..."
}
```

---

### Configuration Upload

#### `POST /api/config/upload`
Upload a JSON, YAML, or CSV configuration file for analysis. Automatically extracts fuzzy input parameters.

**Multipart form:**
- `file` — JSON/YAML/CSV file
- `run_assessment` — `true` to immediately run fuzzy assessment on extracted inputs

**Or JSON body:**
```json
{
  "config": { "debug_mode": false, "ssl_tls_config": true, "cors": "*" },
  "run_assessment": true
}
```

**Response `201`:**
```json
{
  "upload_id": "uuid",
  "format": "json",
  "parsed_keys": ["debug_mode", "ssl_tls_config", "cors"],
  "fuzzy_inputs_extracted": { "debug_mode": 0.8, "ssl_tls_config": 0.1, "access_control": 0.8 },
  "assessment": { "risk_score": 0.72, "risk_level": "HIGH", "overall_score": 28.0, ... }
}
```

#### `GET /api/config/upload`
List all config uploads for the current user.

---

### Fuzzy Rule Management

#### `GET /api/rules`
List all fuzzy rules. Admins see all (including inactive), others see active only.

**Response:**
```json
[
  {
    "id": "uuid", "rule_id": "R01",
    "description": "Missing security headers → HIGH risk",
    "antecedents": [{ "factor": "security_headers", "level": "HIGH" }],
    "consequent": "HIGH", "weight": 1.0, "is_active": true, "source": "predefined"
  }
]
```

---

#### `POST /api/rules`
Create a custom fuzzy rule. **Admin only.**

**Body:**
```json
{
  "rule_id": "R41",
  "description": "Open S3 bucket AND no auth → CRITICAL",
  "antecedents": [
    { "factor": "cloud_config", "level": "VERY_HIGH" },
    { "factor": "authentication_config", "level": "HIGH" }
  ],
  "consequent": "CRITICAL",
  "weight": 1.3
}
```

---

#### `GET /api/rules/<id>`
Get a single rule by UUID.

#### `PUT /api/rules/<id>`
Update a rule. **Admin only.**

#### `DELETE /api/rules/<id>`
Deactivate a rule (soft delete). **Admin only.**

---

### Scans

#### `POST /api/scan`
Submit a URL for security scanning. Runs asynchronously.

**Body:**
```json
{
  "url": "https://example.com",
  "title": "Example.com Audit",
  "environment": "production"
}
```
`environment` options: `production`, `staging`, `development`

**Response `202`:**
```json
{
  "scan_id": "uuid",
  "status": "pending",
  "message": "Scan started. Poll /api/scan/{id} for results.",
  "target_url": "https://example.com",
  "environment": "production",
  "previous_scan_id": "uuid or null"
}
```

---

#### `GET /api/scan/<id>`
Get full scan results including fuzzy assessment, factors, and recommendations.

**Response `200` (completed):**
```json
{
  "id": "uuid", "target_url": "https://example.com", "status": "completed",
  "environment": "production",
  "fuzzy_result": {
    "risk_score": 0.74, "risk_level": "HIGH", "overall_score": 26.0,
    "confidence": 0.68, "category_scores": { "security": 22.1, "configuration": 35.0, ... },
    "triggered_rules": [{ "rule_id": "R02", "description": "...", "firing_strength": 0.91 }],
    "explainability": "Risk assessed as HIGH (score 0.74/1.00)...",
    "fuzzy_inputs": { "security_headers": 0.85, "debug_mode": 0.1, ... }
  },
  "factors": [{ "name": "security_headers", "score_100": 15.0, "linguistic_value": "VERY_HIGH" }],
  "recommendations": [{ "severity": "critical", "title": "...", "remediation": "..." }]
}
```

---

#### `PATCH /api/scan/<id>`
Update scan title or bookmark status.

**Body:** `{ "title": "New Title", "is_bookmarked": true }`

---

#### `DELETE /api/scan/<id>`
Delete a scan and all associated data. Analyst/Admin only.

---

#### `GET /api/scans`
List all scans for the current user with filtering and pagination.

**Query params:**
| Param | Description |
|---|---|
| `status` | `pending`, `running`, `completed`, `failed` |
| `risk_level` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `environment` | `production`, `staging`, `development` |
| `bookmarked` | `true` |
| `search` | URL substring search |
| `page` | Page number (default 1) |
| `page_size` | Results per page (default 20) |

---

### Dashboard

#### `GET /api/dashboard/summary`
Aggregated stats for the current user's dashboard.

**Response `200`:**
```json
{
  "total_scans": 42, "completed_scans": 38, "failed_scans": 2, "running_scans": 2,
  "bookmarked_scans": 5,
  "risk_distribution": { "LOW": 10, "MEDIUM": 15, "HIGH": 8, "CRITICAL": 5 },
  "average_risk_score": 0.54, "average_overall_score": 46.2,
  "best_overall_score": 91.0, "worst_overall_score": 8.5,
  "high_risk_last_7_days": 3,
  "top_misconfigurations": [{ "category": "Security Headers", "title": "...", "count": 12 }]
}
```

---

#### `GET /api/dashboard/history?days=30`
Historical scan trend data for charts.

**Response:** Array of scan entries with `date`, `risk_score`, `risk_level`, `overall_score`, `category_scores`.

---

#### `GET /api/dashboard/recommendations/<scan_id>`
All recommendations for a scan, sorted by severity.

#### `PATCH /api/dashboard/recommendations/<scan_id>`
Mark a recommendation as resolved.

**Body:** `{ "recommendation_id": "uuid", "is_resolved": true }`

---

### Analytics

#### `GET /api/analytics?days=30`
Deep analytics for the current user.

**Response `200`:**
```json
{
  "period_days": 30,
  "total_scans_in_period": 18,
  "average_category_scores": { "security": 45.2, "seo": 72.1, ... },
  "top_performing_scans": [...],
  "worst_performing_scans": [...],
  "most_common_issues": [{ "category": "Authentication", "count": 9 }],
  "daily_scan_counts": [{ "date": "2026-03-01", "count": 3 }]
}
```

---

### What-If Simulation

#### `POST /api/whatif`
Simulate the effect of fixing specific factors without re-scanning.

**Body:**
```json
{
  "scan_id": "uuid",
  "overrides": {
    "debug_mode": 0.0,
    "security_headers": 0.05,
    "authentication_config": 0.1
  }
}
```

**Response `200`:**
```json
{
  "original": { "risk_score": 0.74, "risk_level": "HIGH", ... },
  "simulated": { "risk_score": 0.31, "risk_level": "MEDIUM", ... },
  "risk_score_delta": -0.43,
  "overall_score_delta": 43.0,
  "improvement": true,
  "summary": "Applying overrides improves risk score by 0.4300 (↑43.0 overall score points)."
}
```

---

### Scan Comparison

#### `POST /api/compare`
Compare two scans side by side.

**Body:** `{ "scan_a_id": "uuid", "scan_b_id": "uuid" }`

**Response `201`:**
```json
{
  "comparison_data": {
    "risk_score_diff": -0.12, "overall_score_diff": 12.0,
    "category_diffs": { "security": 15.0, "seo": -3.0 },
    "risk_level_a": "HIGH", "risk_level_b": "MEDIUM",
    "winner": "scan_b_uuid"
  }
}
```

#### `GET /api/compare`
List recent comparisons for the current user.

---

### Reports

#### `POST /api/reports/<scan_id>`
Generate a report for a completed scan.

**Body:** `{ "format": "pdf" }` — options: `pdf`, `csv`, `json`

**Response `201`:**
```json
{
  "report_id": "uuid", "format": "pdf", "file_size": 48320,
  "signed_url": "https://...", "uploaded_to_storage": true
}
```

#### `GET /api/reports/<scan_id>/download?format=pdf`
Retrieve a previously generated report with a signed download URL.

---

### Webhooks

#### `GET /api/webhooks`
List all webhooks for the current user.

#### `POST /api/webhooks`
Register a new webhook endpoint.

**Body:**
```json
{
  "name": "Slack Alerts",
  "url": "https://hooks.slack.com/services/...",
  "events": ["scan.completed", "risk.critical"],
  "secret": "my-hmac-secret"
}
```

Events: `scan.completed`, `scan.failed`, `risk.high`, `risk.critical`

Payloads are signed with `X-Fuzzi-Signature: sha256=<hmac>` when a secret is set.

#### `PUT /api/webhooks/<id>`
Update a webhook.

#### `DELETE /api/webhooks/<id>`
Delete a webhook.

---

### Audit Log

#### `GET /api/audit`
Retrieve audit log entries. Admins see all users' logs; others see only their own.

**Response:**
```json
[
  {
    "id": "uuid", "user_email": "admin@example.com",
    "action": "rule.create", "resource_type": "fuzzy_rule",
    "resource_id": "uuid", "ip_address": "1.2.3.4",
    "created_at": "2026-03-28T14:00:00Z"
  }
]
```

Tracked actions: `auth.login`, `auth.logout`, `auth.password_change`, `profile.update`, `preferences.update`, `scan.create`, `scan.delete`, `rule.create`, `rule.update`, `rule.deactivate`, `config.upload`, `report.generate`, `webhook.create`, `webhook.delete`, `recommendation.resolve`, `admin.user_update`

---

### Admin

#### `GET /api/admin/users`
List all user profiles. **Admin only.**

#### `PATCH /api/admin/users`
Update a user's role or status. **Admin only.**

**Body:** `{ "supabase_uid": "uuid", "role": "analyst", "is_active": true }`

---

## Role-Based Access Control

| Role | Permissions |
|---|---|
| `admin` | Full access — manage rules, users, view all audit logs |
| `analyst` | Submit scans, delete own scans, generate reports, view analytics |
| `developer` | Submit scans only |
| `viewer` | Read-only access to scans and reports |

---

## Database Schema

Run `supabase_schema.sql` in the Supabase SQL Editor to create all tables, indexes, RLS policies, storage buckets, and triggers.

Tables: `user_profiles`, `user_preferences`, `fuzzy_rules`, `scans`, `fuzzy_results`, `factors`, `recommendations`, `reports`, `scan_comparisons`, `config_uploads`, `audit_logs`, `webhooks`

---

## Health Check

`GET /` — returns `{ "status": "ok", "service": "fuzzi-backend", "version": "1.0.0" }`
