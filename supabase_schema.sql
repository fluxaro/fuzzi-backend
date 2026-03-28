-- ============================================================
-- FUZZI — Complete Supabase PostgreSQL Schema
-- Safe to re-run on existing databases.
-- Uses CREATE TABLE IF NOT EXISTS + ADD COLUMN IF NOT EXISTS
-- Run in: Supabase Dashboard → SQL Editor → Run
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- 1. USER PROFILES
-- ============================================================
CREATE TABLE IF NOT EXISTS user_profiles (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    supabase_uid    VARCHAR(255) UNIQUE NOT NULL,
    email           VARCHAR(254) UNIQUE NOT NULL,
    full_name       VARCHAR(255) DEFAULT '',
    role            VARCHAR(20)  DEFAULT 'analyst',
    organization    VARCHAR(255) DEFAULT '',
    avatar_url      VARCHAR(200) DEFAULT '',
    is_active       BOOLEAN      DEFAULT TRUE,
    total_scans     INTEGER      DEFAULT 0,
    created_at      TIMESTAMPTZ  DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  DEFAULT NOW(),
    last_login      TIMESTAMPTZ
);
-- New columns added in v2 (safe to run on existing table)
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS alert_threshold FLOAT;

CREATE INDEX IF NOT EXISTS idx_user_profiles_supabase_uid ON user_profiles(supabase_uid);
CREATE INDEX IF NOT EXISTS idx_user_profiles_email        ON user_profiles(email);

-- ============================================================
-- 2. USER PREFERENCES
-- ============================================================
CREATE TABLE IF NOT EXISTS user_preferences (
    id                    UUID     PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id               UUID     NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    theme                 VARCHAR(10)  DEFAULT 'system',
    email_alerts          BOOLEAN      DEFAULT TRUE,
    alert_on_high_risk    BOOLEAN      DEFAULT TRUE,
    alert_on_critical     BOOLEAN      DEFAULT TRUE,
    default_scan_depth    VARCHAR(20)  DEFAULT 'standard',
    dashboard_layout      JSONB        DEFAULT '{}',
    notifications_enabled BOOLEAN      DEFAULT TRUE,
    created_at            TIMESTAMPTZ  DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  DEFAULT NOW(),
    UNIQUE(user_id)
);
ALTER TABLE user_preferences ADD COLUMN IF NOT EXISTS webhook_url VARCHAR(200) DEFAULT '';

-- ============================================================
-- 3. FUZZY RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS fuzzy_rules (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id     VARCHAR(20) UNIQUE NOT NULL,
    description VARCHAR(500) NOT NULL,
    antecedents JSONB        NOT NULL,
    consequent  VARCHAR(10)  NOT NULL,
    weight      FLOAT        DEFAULT 1.0,
    is_active   BOOLEAN      DEFAULT TRUE,
    source      VARCHAR(100) DEFAULT 'predefined',
    created_by  VARCHAR(255) DEFAULT '',
    created_at  TIMESTAMPTZ  DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fuzzy_rules_active ON fuzzy_rules(is_active);

-- ============================================================
-- 4. SCANS
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       VARCHAR(255) NOT NULL,
    target_url    VARCHAR(2048) NOT NULL,
    title         VARCHAR(255) DEFAULT '',
    status        VARCHAR(20)  DEFAULT 'pending',
    scan_options  JSONB        DEFAULT '{}',
    raw_results   JSONB        DEFAULT '{}',
    html_content  TEXT         DEFAULT '',
    error_message TEXT         DEFAULT '',
    is_bookmarked BOOLEAN      DEFAULT FALSE,
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  DEFAULT NOW()
);
-- New columns added in v2
ALTER TABLE scans ADD COLUMN IF NOT EXISTS environment   VARCHAR(20) DEFAULT 'production';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS previous_scan UUID REFERENCES scans(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_scans_user_id    ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_env        ON scans(environment);

-- ============================================================
-- 5. FUZZY RESULTS
-- ============================================================
CREATE TABLE IF NOT EXISTS fuzzy_results (
    id                UUID   PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id           UUID   UNIQUE NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    risk_score        FLOAT  NOT NULL,
    risk_level        VARCHAR(10) NOT NULL,
    overall_score     FLOAT  DEFAULT 50.0,
    confidence        FLOAT  DEFAULT 0.0,
    category_scores   JSONB  DEFAULT '{}',
    triggered_rules   JSONB  DEFAULT '[]',
    fuzzy_inputs      JSONB  DEFAULT '{}',
    fuzzy_memberships JSONB  DEFAULT '{}',
    aggregate_output  JSONB  DEFAULT '{}',
    explainability    TEXT   DEFAULT '',
    created_at        TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fuzzy_results_scan_id    ON fuzzy_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_fuzzy_results_risk_level ON fuzzy_results(risk_level);

-- ============================================================
-- 6. FACTORS
-- ============================================================
CREATE TABLE IF NOT EXISTS factors (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id          UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name             VARCHAR(100) NOT NULL,
    category         VARCHAR(100) NOT NULL,
    raw_value        FLOAT        NOT NULL,
    score_100        FLOAT        DEFAULT 50.0,
    linguistic_value VARCHAR(20)  NOT NULL,
    details          JSONB        DEFAULT '{}',
    weight           FLOAT        DEFAULT 1.0,
    created_at       TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_factors_scan_id  ON factors(scan_id);
CREATE INDEX IF NOT EXISTS idx_factors_category ON factors(category);

-- ============================================================
-- 7. RECOMMENDATIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS recommendations (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id           UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title             VARCHAR(255) NOT NULL,
    description       TEXT         NOT NULL,
    severity          VARCHAR(10)  NOT NULL,
    category          VARCHAR(100) NOT NULL,
    remediation       TEXT         NOT NULL,
    ref_links         JSONB        DEFAULT '[]',
    triggered_by_rule VARCHAR(255) DEFAULT '',
    is_resolved       BOOLEAN      DEFAULT FALSE,
    created_at        TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recommendations_scan_id  ON recommendations(scan_id);
CREATE INDEX IF NOT EXISTS idx_recommendations_severity ON recommendations(severity);

-- ============================================================
-- 8. REPORTS
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id        UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format         VARCHAR(5)  NOT NULL,
    storage_path   VARCHAR(512) NOT NULL,
    file_size      INTEGER      DEFAULT 0,
    generated_at   TIMESTAMPTZ  DEFAULT NOW(),
    download_count INTEGER      DEFAULT 0,
    UNIQUE(scan_id, format)
);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);

-- ============================================================
-- 9. SCAN COMPARISONS
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_comparisons (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         VARCHAR(255) NOT NULL,
    scan_a_id       UUID         NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scan_b_id       UUID         NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    comparison_data JSONB        DEFAULT '{}',
    created_at      TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_comparisons_user_id ON scan_comparisons(user_id);

-- ============================================================
-- 10. CONFIG UPLOADS
-- ============================================================
CREATE TABLE IF NOT EXISTS config_uploads (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       VARCHAR(255) NOT NULL,
    filename      VARCHAR(255) NOT NULL,
    format        VARCHAR(10)  NOT NULL,
    storage_path  VARCHAR(512) DEFAULT '',
    parsed_config JSONB        DEFAULT '{}',
    status        VARCHAR(20)  DEFAULT 'pending',
    error_message TEXT         DEFAULT '',
    scan_id       UUID         REFERENCES scans(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_config_uploads_user_id ON config_uploads(user_id);

-- ============================================================
-- 11. AUDIT LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       VARCHAR(255) NOT NULL,
    user_email    VARCHAR(254) DEFAULT '',
    action        VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50)  DEFAULT '',
    resource_id   VARCHAR(255) DEFAULT '',
    details       JSONB        DEFAULT '{}',
    ip_address    INET,
    user_agent    TEXT         DEFAULT '',
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id    ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action     ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- ============================================================
-- 12. WEBHOOKS
-- ============================================================
CREATE TABLE IF NOT EXISTS webhooks (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id           VARCHAR(255) NOT NULL,
    name              VARCHAR(100) NOT NULL,
    url               VARCHAR(200) NOT NULL,
    events            JSONB        DEFAULT '[]',
    secret            VARCHAR(255) DEFAULT '',
    is_active         BOOLEAN      DEFAULT TRUE,
    last_triggered_at TIMESTAMPTZ,
    failure_count     INTEGER      DEFAULT 0,
    created_at        TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON webhooks(user_id);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================
ALTER TABLE user_profiles    ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans             ENABLE ROW LEVEL SECURITY;
ALTER TABLE fuzzy_results     ENABLE ROW LEVEL SECURITY;
ALTER TABLE factors           ENABLE ROW LEVEL SECURITY;
ALTER TABLE recommendations   ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports           ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_comparisons  ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_uploads    ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks          ENABLE ROW LEVEL SECURITY;
ALTER TABLE fuzzy_rules       ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "service_role_bypass_profiles"  ON user_profiles;
DROP POLICY IF EXISTS "service_role_bypass_prefs"     ON user_preferences;
DROP POLICY IF EXISTS "service_role_bypass_scans"     ON scans;
DROP POLICY IF EXISTS "service_role_bypass_fuzzy"     ON fuzzy_results;
DROP POLICY IF EXISTS "service_role_bypass_factors"   ON factors;
DROP POLICY IF EXISTS "service_role_bypass_recs"      ON recommendations;
DROP POLICY IF EXISTS "service_role_bypass_reports"   ON reports;
DROP POLICY IF EXISTS "service_role_bypass_compare"   ON scan_comparisons;
DROP POLICY IF EXISTS "service_role_bypass_config"    ON config_uploads;
DROP POLICY IF EXISTS "service_role_bypass_audit"     ON audit_logs;
DROP POLICY IF EXISTS "service_role_bypass_webhooks"  ON webhooks;
DROP POLICY IF EXISTS "service_role_bypass_rules"     ON fuzzy_rules;
DROP POLICY IF EXISTS "users_own_profile"             ON user_profiles;
DROP POLICY IF EXISTS "users_own_preferences"         ON user_preferences;
DROP POLICY IF EXISTS "users_own_scans"               ON scans;
DROP POLICY IF EXISTS "users_own_fuzzy_results"       ON fuzzy_results;
DROP POLICY IF EXISTS "users_own_factors"             ON factors;
DROP POLICY IF EXISTS "users_own_recommendations"     ON recommendations;
DROP POLICY IF EXISTS "users_own_reports"             ON reports;
DROP POLICY IF EXISTS "users_own_comparisons"         ON scan_comparisons;
DROP POLICY IF EXISTS "users_own_config"              ON config_uploads;
DROP POLICY IF EXISTS "users_own_audit"               ON audit_logs;
DROP POLICY IF EXISTS "users_own_webhooks"            ON webhooks;
DROP POLICY IF EXISTS "rules_readable_by_all"         ON fuzzy_rules;
DROP POLICY IF EXISTS "service_role_all"              ON user_profiles;
DROP POLICY IF EXISTS "service_role_all_scans"        ON scans;

-- Service role (Django backend) bypasses all RLS
CREATE POLICY "service_role_bypass_profiles"  ON user_profiles    USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_prefs"     ON user_preferences USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_scans"     ON scans            USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_fuzzy"     ON fuzzy_results    USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_factors"   ON factors          USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_recs"      ON recommendations  USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_reports"   ON reports          USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_compare"   ON scan_comparisons USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_config"    ON config_uploads   USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_audit"     ON audit_logs       USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_webhooks"  ON webhooks         USING (auth.role() = 'service_role');
CREATE POLICY "service_role_bypass_rules"     ON fuzzy_rules      USING (auth.role() = 'service_role');

-- Users access only their own data
CREATE POLICY "users_own_profile"       ON user_profiles    FOR ALL USING (supabase_uid = auth.uid()::text);
CREATE POLICY "users_own_preferences"   ON user_preferences FOR ALL USING (user_id IN (SELECT id FROM user_profiles WHERE supabase_uid = auth.uid()::text));
CREATE POLICY "users_own_scans"         ON scans            FOR ALL USING (user_id = auth.uid()::text);
CREATE POLICY "users_own_fuzzy_results" ON fuzzy_results    FOR ALL USING (scan_id IN (SELECT id FROM scans WHERE user_id = auth.uid()::text));
CREATE POLICY "users_own_factors"       ON factors          FOR ALL USING (scan_id IN (SELECT id FROM scans WHERE user_id = auth.uid()::text));
CREATE POLICY "users_own_recommendations" ON recommendations FOR ALL USING (scan_id IN (SELECT id FROM scans WHERE user_id = auth.uid()::text));
CREATE POLICY "users_own_reports"       ON reports          FOR ALL USING (scan_id IN (SELECT id FROM scans WHERE user_id = auth.uid()::text));
CREATE POLICY "users_own_comparisons"   ON scan_comparisons FOR ALL USING (user_id = auth.uid()::text);
CREATE POLICY "users_own_config"        ON config_uploads   FOR ALL USING (user_id = auth.uid()::text);
CREATE POLICY "users_own_audit"         ON audit_logs       FOR SELECT USING (user_id = auth.uid()::text);
CREATE POLICY "users_own_webhooks"      ON webhooks         FOR ALL USING (user_id = auth.uid()::text);
CREATE POLICY "rules_readable_by_all"   ON fuzzy_rules      FOR SELECT USING (auth.role() = 'authenticated');

-- ============================================================
-- STORAGE BUCKETS
-- ============================================================
INSERT INTO storage.buckets (id, name, public)
VALUES
    ('fuzzi-reports',     'fuzzi-reports',     FALSE),
    ('fuzzi-screenshots', 'fuzzi-screenshots', FALSE),
    ('fuzzi-artifacts',   'fuzzi-artifacts',   FALSE),
    ('fuzzi-configs',     'fuzzi-configs',     FALSE)
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- AUTO-UPDATE updated_at TRIGGER
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_user_profiles_updated_at    ON user_profiles;
DROP TRIGGER IF EXISTS trg_user_preferences_updated_at ON user_preferences;
DROP TRIGGER IF EXISTS trg_fuzzy_rules_updated_at      ON fuzzy_rules;

CREATE TRIGGER trg_user_profiles_updated_at
    BEFORE UPDATE ON user_profiles FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_user_preferences_updated_at
    BEFORE UPDATE ON user_preferences FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_fuzzy_rules_updated_at
    BEFORE UPDATE ON fuzzy_rules FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================
-- DONE
-- ============================================================
