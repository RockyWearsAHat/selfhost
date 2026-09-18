-- Insert sample subdomains
INSERT OR IGNORE INTO subdomains (id, name, url, description, is_public) VALUES
('subdomain_admin', 'admin', 'https://admin.rockywearsahat.com', 'Administration console', 0),
('subdomain_ai', 'ai', 'https://ai.rockywearsahat.com', 'AI tools', 0),
('subdomain_reports', 'reports', 'https://reports.rockywearsahat.com', 'Analytics dashboard', 0),
('subdomain_git', 'git', 'https://git.rockywearsahat.com', 'Git repositories', 0),
('subdomain_mail', 'mail', 'https://mail.rockywearsahat.com', 'Email interface', 0),
('subdomain_vault', 'vault', 'https://vault.rockywearsahat.com', 'Secrets vault', 0),
('subdomain_vpn', 'vpn', 'https://vpn.rockywearsahat.com', 'VPN management', 0),
('subdomain_api', 'api', 'https://api.rockywearsahat.com', 'API gateway', 0);
