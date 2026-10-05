-- Schema of the v3.0.0 database (commit c884dde, before the relay tree): reproduced verbatim from
-- store.go@c884dde, followed by fake, non-sensitive representative rows. Used by the migration tests.

CREATE TABLE IF NOT EXISTS agents (
    hostname        TEXT PRIMARY KEY,
    public_key_pem  TEXT NOT NULL,
    token_jti       TEXT,
    enrolled_at     TIMESTAMP,
    last_seen       TIMESTAMP,
    status          TEXT NOT NULL DEFAULT 'disconnected',
    suspended       BOOLEAN NOT NULL DEFAULT FALSE,
    vars            TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS authorized_keys (
    hostname        TEXT PRIMARY KEY,
    public_key_pem  TEXT NOT NULL,
    approved_at     TIMESTAMP NOT NULL,
    approved_by     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist (
    jti             TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    revoked_at      TIMESTAMP NOT NULL,
    reason          TEXT,
    expires_at      TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist (expires_at);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents (status);

CREATE TABLE IF NOT EXISTS server_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id               TEXT PRIMARY KEY,
    token_hash       TEXT NOT NULL UNIQUE,
    hostname_pattern TEXT NOT NULL,
    reusable         INTEGER NOT NULL DEFAULT 0,
    use_count        INTEGER NOT NULL DEFAULT 0,
    last_used_at     INTEGER,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER,
    created_by       TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens (token_hash);

CREATE TABLE IF NOT EXISTS plugin_tokens (
    id                       TEXT PRIMARY KEY,
    token_hash               TEXT NOT NULL UNIQUE,
    description              TEXT,
    role                     TEXT NOT NULL DEFAULT 'plugin',
    allowed_ips              TEXT,
    allowed_hostname_pattern TEXT,
    created_at               INTEGER NOT NULL,
    expires_at               INTEGER,
    last_used_at             INTEGER,
    last_used_ip             TEXT,
    revoked                  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_plugin_tokens_hash ON plugin_tokens (token_hash);

CREATE TABLE IF NOT EXISTS action_log (
    id              TEXT PRIMARY KEY,
    event           TEXT NOT NULL,
    hostname        TEXT NOT NULL,
    action_type     TEXT NOT NULL,
    action_index    INTEGER NOT NULL,
    config_snapshot TEXT NOT NULL,
    success         INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    duration_ms     INTEGER,
    executed_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_log_hostname ON action_log (hostname, executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_log_event    ON action_log (event,    executed_at DESC);

-- Phase 12: Proxy/Gateway — relay node registry and hostname routing
CREATE TABLE IF NOT EXISTS relay_nodes (
    id          TEXT PRIMARY KEY,
    relay_id    TEXT NOT NULL UNIQUE,
    url         TEXT,
    description TEXT,
    token_hash  TEXT,
    mode        TEXT NOT NULL DEFAULT 'pull',
    is_proxy    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER,
    status      TEXT NOT NULL DEFAULT 'disconnected'
);
CREATE INDEX IF NOT EXISTS idx_relay_nodes_relay_id ON relay_nodes (relay_id);
CREATE INDEX IF NOT EXISTS idx_relay_nodes_status   ON relay_nodes (status);

CREATE TABLE IF NOT EXISTS relay_routing (
    hostname    TEXT PRIMARY KEY,
    relay_id    TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    FOREIGN KEY (relay_id) REFERENCES relay_nodes(relay_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_relay_routing_relay_id ON relay_routing (relay_id);

-- ── representative rows ────────────────────────────────────────────────────
INSERT INTO agents (hostname, public_key_pem, token_jti, enrolled_at, status, suspended, vars) VALUES
  ('agent-a', 'FAKE-PEM-A', 'jti-agent-a', '2026-01-01T00:00:00Z', 'connected', 0, '{"env":"prod"}'),
  ('agent-b', 'FAKE-PEM-B', 'jti-agent-b', '2026-01-02T00:00:00Z', 'disconnected', 1, '{}');
INSERT INTO authorized_keys (hostname, public_key_pem, approved_at, approved_by) VALUES
  ('agent-c', 'FAKE-PEM-C', '2026-01-03T00:00:00Z', 'ci');
INSERT INTO blacklist (jti, hostname, revoked_at, reason, expires_at) VALUES
  ('jti-old-revoked', 'agent-z', '2026-01-04T00:00:00Z', 'legacy revoke', '2099-01-01T00:00:00Z');
INSERT INTO server_config (key, value, updated_at) VALUES
  ('jwt_secret_current', 'legacy-secret', '2026-01-01T00:00:00Z');
INSERT INTO enrollment_tokens (id, token_hash, hostname_pattern, reusable, use_count, created_at, created_by) VALUES
  ('enr-1', 'hash-enr-1', '^agent-.*$', 1, 2, 1700000000, 'admin');
INSERT INTO plugin_tokens (id, token_hash, description, role, created_at, revoked) VALUES
  ('plg-1', 'hash-plg-1', 'legacy plugin', 'plugin', 1700000000, 0);
-- a pull relay (token_hash = sha256 of its JWT, no JTI: pre-#153), a PUSH relay whose token was stored
-- IN CLEAR (the way v3.0 did), and a relay with no routes
INSERT INTO relay_nodes (id, relay_id, url, description, token_hash, mode, is_proxy, created_at, status) VALUES
  ('u-pull', 'legacy-pull', NULL, 'old pull relay', 'sha256-of-the-old-jwt', 'pull', 0, 1700000000, 'connected'),
  ('u-push', 'legacy-push', 'wss://legacy-push.invalid:7772', 'old push relay', 'legacy-plain-push-token-0123456789', 'push', 0, 1700000001, 'disconnected'),
  ('u-idle', 'legacy-idle', NULL, 'relay without hosts', 'sha256-idle', 'pull', 1, 1700000002, 'disconnected');
-- routes WITHOUT hop_type / relay_chain (those columns do not exist yet)
INSERT INTO relay_routing (hostname, relay_id, updated_at) VALUES
  ('host-1', 'legacy-pull', 1700000010),
  ('host-2', 'legacy-pull', 1700000011),
  ('host-3', 'legacy-push', 1700000012);
