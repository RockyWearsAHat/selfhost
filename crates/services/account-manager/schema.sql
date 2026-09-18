-- Core Tables for VPN Account System
-- Database: SQLite3 (default) or PostgreSQL

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    passkey_credential_id BLOB NOT NULL,
    public_key TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP,
    suspended_at TIMESTAMP,
    last_login TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'pending'
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    category TEXT,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User roles (many-to-many)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by TEXT REFERENCES users(id),
    expires_at TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- Role permissions (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- VPN Locations
CREATE TABLE IF NOT EXISTS vpn_locations (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    region TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Location permissions
CREATE TABLE IF NOT EXISTS location_permissions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    location_id TEXT NOT NULL REFERENCES vpn_locations(id) ON DELETE CASCADE,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by TEXT REFERENCES users(id),
    expires_at TIMESTAMP,
    UNIQUE(user_id, location_id)
);

-- Action approvals (specific action permissions)
CREATE TABLE IF NOT EXISTS action_approvals (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    location_id TEXT REFERENCES vpn_locations(id),
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by TEXT REFERENCES users(id),
    approved_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Invites
CREATE TABLE IF NOT EXISTS invites (
    id TEXT PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_by TEXT REFERENCES users(id),
    used_at TIMESTAMP,
    preset_role_id TEXT REFERENCES roles(id)
);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT,
    revoked_at TIMESTAMP
);

-- Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    status TEXT NOT NULL,
    error_message TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT
);

-- VPN Access Log
CREATE TABLE IF NOT EXISTS vpn_access_log (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    location_id TEXT NOT NULL REFERENCES vpn_locations(id),
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    error_reason TEXT
);

-- Image Authentication
CREATE TABLE IF NOT EXISTS image_auth (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seed TEXT NOT NULL UNIQUE,
    public_key TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMP,
    rotations_count INTEGER DEFAULT 0
);

-- Default Roles Setup
-- Admin: full access
-- Operator: create, read, write permissions
-- Viewer: read-only permissions

INSERT OR IGNORE INTO roles (id, name, description) VALUES
('role_admin', 'Administrator', 'Full access to all system features'),
('role_operator', 'Operator', 'Can manage VPN locations and users'),
('role_viewer', 'Viewer', 'Read-only access to logs and status');

-- Default Permissions
INSERT OR IGNORE INTO permissions (id, name, category, description) VALUES
('perm_user_create', 'Create Users', 'user_management', 'Create new user accounts'),
('perm_user_edit', 'Edit Users', 'user_management', 'Modify existing user accounts'),
('perm_user_delete', 'Delete Users', 'user_management', 'Delete or suspend user accounts'),
('perm_role_manage', 'Manage Roles', 'user_management', 'Create and modify roles'),
('perm_location_create', 'Create Locations', 'vpn_management', 'Create new VPN locations'),
('perm_location_edit', 'Edit Locations', 'vpn_management', 'Modify VPN location settings'),
('perm_location_delete', 'Delete Locations', 'vpn_management', 'Delete VPN locations'),
('perm_location_access', 'Access Locations', 'vpn_access', 'Connect to VPN locations'),
('perm_audit_view', 'View Audit Logs', 'audit', 'Access audit log entries'),
('perm_admin_console', 'Admin Console', 'admin', 'Access administrator console');

-- Role-Permission mappings
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES
('role_admin', 'perm_user_create'),
('role_admin', 'perm_user_edit'),
('role_admin', 'perm_user_delete'),
('role_admin', 'perm_role_manage'),
('role_admin', 'perm_location_create'),
('role_admin', 'perm_location_edit'),
('role_admin', 'perm_location_delete'),
('role_admin', 'perm_location_access'),
('role_admin', 'perm_audit_view'),
('role_admin', 'perm_admin_console'),
('role_operator', 'perm_location_create'),
('role_operator', 'perm_location_edit'),
('role_operator', 'perm_location_access'),
('role_operator', 'perm_audit_view'),
('role_viewer', 'perm_location_access'),
('role_viewer', 'perm_audit_view');

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

-- Add access_level column to users (if not exists)
ALTER TABLE users ADD COLUMN access_level TEXT DEFAULT 'full_access';
ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT 'admin';

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

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_location_permissions_user_id ON location_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_location_permissions_location_id ON location_permissions(location_id);
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_user_id ON vpn_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_token ON vpn_sessions(token);
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_expires_at ON vpn_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_subdomains_name ON subdomains(name);
CREATE INDEX IF NOT EXISTS idx_site_permissions_user_id ON site_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_site_permissions_subdomain_id ON site_permissions(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_site_permissions_expires_at ON site_permissions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_access_profiles_user_id ON user_access_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_vpn_access_log_user_id ON vpn_access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_vpn_access_log_timestamp ON vpn_access_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_subdomain_audit_log_actor ON subdomain_audit_log(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_subdomain_audit_log_user_id ON subdomain_audit_log(user_id);
