# Fuzzi Backend — Web Security Auditing Platform

## Quick Start

### 1. Set your database password in `.env`

Open `.env` and set `DB_PASSWORD` to your Supabase database password:
- Go to **Supabase Dashboard → Project Settings → Database**
- Copy the **Database password** (not the JWT key)

### 2. Run the SQL schema in Supabase

- Go to **Supabase Dashboard → SQL Editor**
- Paste and run the contents of `supabase_schema.sql`

### 3. Run Django migrations

```bash
cd fuzzi_backend
python3 manage.py migrate
```

### 4. Seed storage buckets and demo user

```bash
python3 seed.py
```

Demo credentials: `admin@fuzzi.dev` / `Fuzzi@Admin2024!`

### 5. Start the server

```bash
python3 manage.py runserver 0.0.0.0:8000
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/signup` | No | Create account |
| POST | `/api/login` | No | Login, returns JWT |
| POST | `/api/logout` | Yes | Invalidate session |
| GET | `/api/me` | Yes | Get/update profile |
| POST | `/api/scan` | Yes | Submit URL for scan |
| GET | `/api/scan/:id` | Yes | Get scan results |
| DELETE | `/api/scan/:id` | Yes | Delete scan |
| GET | `/api/scans` | Yes | List all scans |
| GET | `/api/dashboard/summary` | Yes | Stats & risk counts |
| GET | `/api/dashboard/history` | Yes | Trend data |
| GET | `/api/dashboard/recommendations/:scan_id` | Yes | Recommendations |
| POST | `/api/whatif` | Yes | What-if simulation |
| POST | `/api/reports/:scan_id` | Yes | Generate PDF report |
| GET | `/api/reports/:scan_id/download` | Yes | Get signed PDF URL |
| GET | `/api/admin/users` | Admin | List all users |

### Authentication

All protected endpoints require:
```
Authorization: Bearer <supabase_access_token>
```

### Example: Submit a scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Example: What-if simulation

```bash
curl -X POST http://localhost:8000/api/whatif \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "YOUR_SCAN_UUID",
    "overrides": {
      "security_headers": 0.1,
      "debug_mode": 0.0
    }
  }'
```

---

## Fuzzy Logic Engine

Inputs (0.0 = safe, 1.0 = maximum risk):
- `security_headers` — missing HTTP security headers
- `authentication_config` — weak auth setup
- `directory_permissions` — exposed paths/dirs
- `error_handling` — verbose error messages
- `debug_mode` — debug indicators active
- `access_control` — CORS/access control issues
- `cloud_config` — cloud misconfiguration signals

Output:
```json
{
  "risk_score": 0.80,
  "risk_level": "HIGH",
  "confidence": 0.50,
  "triggered_rules": [...],
  "fuzzy_inputs": {...},
  "fuzzy_memberships": {...},
  "aggregate_output": {...}
}
```

Risk levels: `LOW` (0–0.35) · `MEDIUM` (0.35–0.65) · `HIGH` (0.65–0.85) · `CRITICAL` (0.85–1.0)
