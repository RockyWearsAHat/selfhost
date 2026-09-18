-- VPN Authentication + Subdomain Access Control Migration
-- Only adds NEW tables, doesn't modify existing ones

-- Add columns to users table if they don't exist
ALTER TABLE users ADD COLUMN access_level TEXT DEFAULT 'full_access';
ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT 'admin';

-- VPN Sessions (for token-based auth)
CREATE TABLE IF NOT EXISTS vpn_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    ip_address TEXT
);

-- Subdomains/Sites
CREATE TABLE IF NOT EXISTS subdomains (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    description TEXT,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT REFERENCES users(id),
    disabled_at TIMESTAMP
);

-- Site Permissions
CREATE TABLE IF NOT EXISTS site_permissions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subdomain_id TEXT NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    action TEXT NOT NULL DEFAULT 'access',
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by TEXT REFERENCES users(id),
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, subdomain_id, action)
);

-- User Access Profiles
CREATE TABLE IF NOT EXISTS user_access_profiles (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    access_level TEXT NOT NULL DEFAULT 'full_access',
    default_action TEXT NOT NULL DEFAULT 'access',
    last_modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_by TEXT REFERENCES users(id),
    notes TEXT
);

-- Subdomain Audit Log
CREATE TABLE IF NOT EXISTS subdomain_audit_log (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,
    subdomain_id TEXT REFERENCES subdomains(id),
    user_id TEXT REFERENCES users(id),
    old_value TEXT,
    new_value TEXT,
    status TEXT NOT NULL,
    error_message TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT
);

-- Insert sample subdomains
INSERT OR IGNORE INTO subdomains (id, name, url, description, is_public) VALUES
('subdomain_admin', 'admin', 'https://admin.rockywearsahat.com', 'Administration console', FALSE),
('subdomain_ai', 'ai', 'https://ai.rockywearsahat.com', 'AI tools', FALSE),
('subdomain_reports', 'reports', 'https://reports.rockywearsahat.com', 'Analytics dashboard', FALSE),
('subdomain_git', 'git', 'https://git.rockywearsahat.com', 'Git repositories', FALSE),
('subdomain_mail', 'mail', 'https://mail.rockywearsahat.com', 'Email interface', FALSE),
('subdomain_vault', 'vault', 'https://vault.rockywearsahat.com', 'Secrets vault', FALSE),
('subdomain_vpn', 'vpn', 'https://vpn.rockywearsahat.com', 'VPN management', FALSE),
('subdomain_api', 'api', 'https://api.rockywearsahat.com', 'API gateway', FALSE);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_user_id ON vpn_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_token ON vpn_sessions(token);
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_expires_at ON vpn_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_subdomains_name ON subdomains(name);
CREATE INDEX IF NOT EXISTS idx_site_permissions_user_id ON site_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_site_permissions_subdomain_id ON site_permissions(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_site_permissions_expires_at ON site_permissions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_access_profiles_user_id ON user_access_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_subdomain_audit_log_actor ON subdomain_audit_log(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_subdomain_audit_log_user_id ON subdomain_audit_log(user_id);
