-- IoT Prompt Injection Lab — Database Schema & Seed Data

CREATE TABLE telemetry (
    id SERIAL PRIMARY KEY,
    sensor_id VARCHAR(64) NOT NULL,
    value DOUBLE PRECISION,
    unit VARCHAR(16),
    description TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE flags (
    id SERIAL PRIMARY KEY,
    flag_name VARCHAR(64) NOT NULL,
    flag_value VARCHAR(256) NOT NULL
);

INSERT INTO flags (flag_name, flag_value)
VALUES ('ctf_flag', 'FLAG{mqtt_to_llm_injection_chain_complete}');

-- Seed normal telemetry so the agent has realistic context
INSERT INTO telemetry (sensor_id, value, unit, description) VALUES
    ('TEMP-001', 22.1, 'celsius', 'Office temperature sensor - normal range'),
    ('TEMP-002', 23.8, 'celsius', 'Server room temperature - within limits'),
    ('HUM-001',  45.2, 'percent', 'Warehouse humidity sensor'),
    ('PRESS-001', 1013.25, 'hPa', 'Atmospheric pressure - standard'),
    ('TEMP-003', 19.5, 'celsius', 'Cold storage monitoring point');

-- Read-only role used by the patched agent (no access to flags table)
CREATE ROLE lab_readonly WITH LOGIN PASSWORD 'lab_readonly';
GRANT CONNECT ON DATABASE injection_lab TO lab_readonly;
GRANT USAGE ON SCHEMA public TO lab_readonly;
GRANT SELECT ON telemetry TO lab_readonly;
-- Explicitly NO grant on flags table
