-- ============================================================
-- Fuzzi Security Platform — Supabase SQL Schema
-- Run this entire file in: Supabase Dashboard → SQL Editor
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- 1. USER PROFILES
-- ============================================================
CREATE TABLE IF NOT EXISTS user_profiles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    supabase_uid    TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    full_name       TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'analyst'
                        CHECK (role IN ('admin', 'analyst', 'viewer')),
    organization    TEXT NOT NULL DEFAULT '',
    avatar_url      TEXT NOT NULL DEFAULT '',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    total_scans     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login      TIMESTAMPTZ
);

-- ============================================================
-- 2. USER PREFERENCES
-- ============================================================
CREATE TABLE IF NOT EXISTS user_preferences (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id                 UUID UNIQUE NOT NULL
                                REFERENCES user_profiles(id) ON DELETE CASCADE,
    theme                   TEXT NOT NULL DEFAULT 'system'
                                CHECK (theme IN ('light', 'dark', 'system')),
    email_alerts            BOOLEAN NOT NULL DEFAULT TRUE,
    alert_on_high_risk      BOOLEAN NOT NULL DEFAULT TRUE,
    alert_on_critical       BOOLEAN NOT NULL DEFAULT TRUE,
    default_scan_depth      TEXT NOT NULL DEFAULT 'standard',
    dashboard_layout        JSONB NOT NULL DEFAULT '{}',
    notifications_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 3. SCANS
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         TEXT NOT NULL,
    target_url      TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    scan_options    JSONB NOT NULL DEFAULT '{}',
    raw_results     JSONB NOT NULL DEFAULT '{}',
    html_content    TEXT NOT NULL DEFAULT '',
    error_message   TEXT NOT NULL DEFAULT '',
    is_bookmarked   BOOLEAN NOT NULL DEFAULT FALSE,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 4. FUZZY RESULTS
-- ============================================================
CREATE TABLE IF NOT EXISTS fuzzy_results (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID UNIQUE NOT NULL
                            REFERENCES scans(id) ON DELETE CASCADE,
    risk_score          FLOAT NOT NULL,
    risk_level          TEXT NOT NULL
                            CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    overall_score       FLOAT NOT NULL DEFAULT 50.0,
    confidence          FLOAT NOT NULL DEFAULT 0.0,
    category_scores     JSONB NOT NULL DEFAULT '{}',
    triggered_rules     JSONB NOT NULL DEFAULT '[]',
    fuzzy_inputs        JSONB NOT NULL DEFAULT '{}',
    fuzzy_memberships   JSONB NOT NULL DEFAULT '{}',
    aggregate_output    JSONB NOT NULL DEFAULT '{}',
    explainability      TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 5. FACTORS
-- ============================================================
CREATE TABLE IF NOT EXISTS factors (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID NOT NULL
                            REFERENCES scans(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    category            TEXT NOT NULL,
    raw_value           FLOAT NOT NULL,
    score_100           FLOAT NOT NULL DEFAULT 50.0,
    linguistic_value    TEXT NOT NULL,
    details             JSONB NOT NULL DEFAULT '{}',
    weight              FLOAT NOT NULL DEFAULT 1.0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 6. RECOMMENDATIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS recommendations (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID NOT NULL
                            REFERENCES scans(id) ON DELETE CASCADE,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    severity            TEXT NOT NULL
                            CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    category            TEXT NOT NULL,
    remediation         TEXT NOT NULL,
    ref_links           JSONB NOT NULL DEFAULT '[]',
    triggered_by_rule   TEXT NOT NULL DEFAULT '',
    is_resolved         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 7. REPORTS
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL
                        REFERENCES scans(id) ON DELETE CASCADE,
    format          TEXT NOT NULL DEFAULT 'pdf'
                        CHECK (format IN ('pdf', 'csv')),
    storage_path    TEXT NOT NULL,
    file_size       INTEGER NOT NULL DEFAULT 0,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    download_count  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (scan_id, format)
);

-- ============================================================
-- 8. SCAN COMPARISONS
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_comparisons (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             TEXT NOT NULL,
    scan_a_id           UUID NOT NULL
                            REFERENCES scans(id) ON DELETE CASCADE,
    scan_b_id           UUID NOT NULL
                            REFERENCES scans(id) ON DELETE CASCADE,
    comparison_data     JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 9. DJANGO MIGRATIONS TRACKER
-- ============================================================
CREATE TABLE IF NOT EXISTS django_migrations (
    id          BIGSERIAL PRIMARY KEY,
    app         TEXT NOT NULL,
    name        TEXT NOT NULL,
    applied     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 10. INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_scans_user_id         ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status          ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at      ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_bookmarked      ON scans(is_bookmarked) WHERE is_bookmarked = TRUE;
CREATE INDEX IF NOT EXISTS idx_fuzzy_risk_level      ON fuzzy_results(risk_level);
CREATE INDEX IF NOT EXISTS idx_fuzzy_overall_score   ON fuzzy_results(overall_score DESC);
CREATE INDEX IF NOT EXISTS idx_factors_scan_id       ON factors(scan_id);
CREATE INDEX IF NOT EXISTS idx_recs_scan_id          ON recommendations(scan_id);
CREATE INDEX IF NOT EXISTS idx_recs_severity         ON recommendations(severity);
CREATE INDEX IF NOT EXISTS idx_recs_resolved         ON recommendations(is_resolved);
CREATE INDEX IF NOT EXISTS idx_comparisons_user_id   ON scan_comparisons(user_id);

-- ============================================================
-- 11. AUTO-UPDATE updated_at TRIGGER
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_user_profiles_updated_at   ON user_profiles;
DROP TRIGGER IF EXISTS trg_user_preferences_updated_at ON user_preferences;
DROP TRIGGER IF EXISTS trg_scans_updated_at            ON scans;

CREATE TRIGGER trg_user_profiles_updated_at
    BEFORE UPDATE ON user_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_user_preferences_updated_at
    BEFORE UPDATE ON user_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_scans_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================
-- 12. ROW LEVEL SECURITY (RLS)
-- ============================================================
ALTER TABLE user_profiles    ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans             ENABLE ROW LEVEL SECURITY;
ALTER TABLE fuzzy_results     ENABLE ROW LEVEL SECURITY;
ALTER TABLE factors           ENABLE ROW LEVEL SECURITY;
ALTER TABLE recommendations   ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports           ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_comparisons  ENABLE ROW LEVEL SECURITY;

-- user_profiles
DROP POLICY IF EXISTS "user_profiles_select" ON user_profiles;
DROP POLICY IF EXISTS "user_profiles_update" ON user_profiles;
CREATE POLICY "user_profiles_select" ON user_profiles
    FOR SELECT USING (auth.uid()::text = supabase_uid);
CREATE POLICY "user_profiles_update" ON user_profiles
    FOR UPDATE USING (auth.uid()::text = supabase_uid);

-- user_preferences
DROP POLICY IF EXISTS "user_preferences_all" ON user_preferences;
CREATE POLICY "user_preferences_all" ON user_preferences
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM user_profiles
            WHERE user_profiles.id = user_preferences.user_id
              AND user_profiles.supabase_uid = auth.uid()::text
        )
    );

-- scans
DROP POLICY IF EXISTS "scans_select" ON scans;
DROP POLICY IF EXISTS "scans_insert" ON scans;
DROP POLICY IF EXISTS "scans_update" ON scans;
DROP POLICY IF EXISTS "scans_delete" ON scans;
CREATE POLICY "scans_select" ON scans FOR SELECT USING (auth.uid()::text = user_id);
CREATE POLICY "scans_insert" ON scans FOR INSERT WITH CHECK (auth.uid()::text = user_id);
CREATE POLICY "scans_update" ON scans FOR UPDATE USING (auth.uid()::text = user_id);
CREATE POLICY "scans_delete" ON scans FOR DELETE USING (auth.uid()::text = user_id);

-- fuzzy_results
DROP POLICY IF EXISTS "fuzzy_results_select" ON fuzzy_results;
CREATE POLICY "fuzzy_results_select" ON fuzzy_results
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM scans WHERE scans.id = fuzzy_results.scan_id
                AND scans.user_id = auth.uid()::text)
    );

-- factors
DROP POLICY IF EXISTS "factors_select" ON factors;
CREATE POLICY "factors_select" ON factors
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM scans WHERE scans.id = factors.scan_id
                AND scans.user_id = auth.uid()::text)
    );

-- recommendations
DROP POLICY IF EXISTS "recommendations_select" ON recommendations;
DROP POLICY IF EXISTS "recommendations_update" ON recommendations;
CREATE POLICY "recommendations_select" ON recommendations
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM scans WHERE scans.id = recommendations.scan_id
                AND scans.user_id = auth.uid()::text)
    );
CREATE POLICY "recommendations_update" ON recommendations
    FOR UPDATE USING (
        EXISTS (SELECT 1 FROM scans WHERE scans.id = recommendations.scan_id
                AND scans.user_id = auth.uid()::text)
    );

-- reports
DROP POLICY IF EXISTS "reports_select" ON reports;
CREATE POLICY "reports_select" ON reports
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM scans WHERE scans.id = reports.scan_id
                AND scans.user_id = auth.uid()::text)
    );

-- scan_comparisons
DROP POLICY IF EXISTS "scan_comparisons_all" ON scan_comparisons;
CREATE POLICY "scan_comparisons_all" ON scan_comparisons
    FOR ALL USING (auth.uid()::text = user_id);

-- ============================================================
-- 13. STORAGE BUCKETS
-- ============================================================
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES
    ('fuzzi-reports',      'fuzzi-reports',      FALSE, 52428800, ARRAY['application/pdf', 'text/csv']),
    ('fuzzi-screenshots',  'fuzzi-screenshots',  FALSE, 10485760, ARRAY['image/png', 'image/jpeg', 'image/webp']),
    ('fuzzi-artifacts',    'fuzzi-artifacts',    FALSE, 52428800, NULL)
ON CONFLICT (id) DO NOTHING;

-- Storage RLS: only owner can access their files
DROP POLICY IF EXISTS "reports_storage_select" ON storage.objects;
DROP POLICY IF EXISTS "reports_storage_insert" ON storage.objects;
CREATE POLICY "reports_storage_insert" ON storage.objects
    FOR INSERT WITH CHECK (
        bucket_id IN ('fuzzi-reports', 'fuzzi-screenshots', 'fuzzi-artifacts')
        AND auth.role() = 'authenticated'
    );
CREATE POLICY "reports_storage_select" ON storage.objects
    FOR SELECT USING (
        bucket_id IN ('fuzzi-reports', 'fuzzi-screenshots', 'fuzzi-artifacts')
        AND auth.role() = 'authenticated'
    );
