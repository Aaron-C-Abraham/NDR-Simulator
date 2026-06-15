-- NDR Test Environment Simulator — MySQL Schema
-- Database: netsim_ndr

CREATE DATABASE IF NOT EXISTS netsim_ndr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE netsim_ndr;

-- devices: simulated network devices in the topology
CREATE TABLE IF NOT EXISTS devices (
    id           VARCHAR(36)  NOT NULL PRIMARY KEY,
    name         VARCHAR(128) NOT NULL,
    device_type  VARCHAR(64)  NOT NULL,  -- router, switch, firewall, server, workstation, iot, wireless_ap
    ip_address   VARCHAR(45)  NOT NULL,
    mac_address  VARCHAR(17)  NOT NULL,
    os_type      VARCHAR(64)  NOT NULL,
    vendor       VARCHAR(64)  NOT NULL,
    network_zone VARCHAR(64)  NOT NULL,  -- dmz, internal, external, management
    telemetry    JSON         NOT NULL,  -- {"syslog":true,"netflow":true,"pcap":false}
    status       VARCHAR(16)  NOT NULL DEFAULT 'active',
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_device_type (device_type),
    INDEX idx_network_zone (network_zone)
) ENGINE=InnoDB;

-- scenarios: named attack scenario definitions
CREATE TABLE IF NOT EXISTS scenarios (
    id           VARCHAR(36)   NOT NULL PRIMARY KEY,
    name         VARCHAR(256)  NOT NULL,
    description  TEXT          NOT NULL,
    category     VARCHAR(64)   NOT NULL,  -- beaconing, lateral_movement, exfiltration, ransomware, etc.
    mitre_techniques JSON      NOT NULL,  -- ["T1071.001","T1041"]
    attack_steps JSON          NOT NULL,  -- ordered list of attack module + params
    expected_alerts JSON       NOT NULL,  -- what NDR should detect
    duration_secs INT          NOT NULL DEFAULT 300,
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category)
) ENGINE=InnoDB;

-- test_runs: execution records for scenario runs
CREATE TABLE IF NOT EXISTS test_runs (
    id              VARCHAR(36)  NOT NULL PRIMARY KEY,
    scenario_id     VARCHAR(36)  NOT NULL,
    scenario_name   VARCHAR(256) NOT NULL,
    status          VARCHAR(32)  NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed, aborted
    started_at      DATETIME,
    completed_at    DATETIME,
    duration_secs   INT,
    attacker_ip     VARCHAR(45)  NOT NULL,
    target_ips      JSON         NOT NULL,
    config_snapshot JSON         NOT NULL,  -- full scenario config at time of run
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scenario_id) REFERENCES scenarios(id),
    INDEX idx_status (status),
    INDEX idx_started_at (started_at)
) ENGINE=InnoDB;

-- run_events: telemetry events generated during a test run
CREATE TABLE IF NOT EXISTS run_events (
    id            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id        VARCHAR(36)  NOT NULL,
    event_time    DATETIME(3)  NOT NULL,
    event_type    VARCHAR(64)  NOT NULL,  -- syslog, netflow, sflow, pcap, attack_step
    source_device VARCHAR(36),
    source_ip     VARCHAR(45),
    dest_ip       VARCHAR(45),
    protocol      VARCHAR(16),
    payload       JSON         NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES test_runs(id),
    INDEX idx_run_event_type (run_id, event_type),
    INDEX idx_event_time (event_time)
) ENGINE=InnoDB;

-- ndr_alerts: alerts received from the NDR agent during a test run
CREATE TABLE IF NOT EXISTS ndr_alerts (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id       VARCHAR(36)  NOT NULL,
    alert_time   DATETIME(3)  NOT NULL,
    alert_type   VARCHAR(128) NOT NULL,
    severity     VARCHAR(32)  NOT NULL,  -- critical, high, medium, low, informational
    source_ip    VARCHAR(45),
    dest_ip      VARCHAR(45),
    mitre_id     VARCHAR(32),
    description  TEXT,
    raw_payload  JSON         NOT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES test_runs(id),
    INDEX idx_run_alert_type (run_id, alert_type),
    INDEX idx_severity (severity)
) ENGINE=InnoDB;

-- scoring_results: detection scoring per test run
CREATE TABLE IF NOT EXISTS scoring_results (
    id                   BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id               VARCHAR(36) NOT NULL UNIQUE,
    total_score          FLOAT       NOT NULL DEFAULT 0,
    detection_rate       FLOAT       NOT NULL DEFAULT 0,  -- 0.0–1.0
    false_positive_rate  FLOAT       NOT NULL DEFAULT 0,
    true_positives       INT         NOT NULL DEFAULT 0,
    false_positives      INT         NOT NULL DEFAULT 0,
    false_negatives      INT         NOT NULL DEFAULT 0,
    ttd_seconds          FLOAT,     -- time-to-detect in seconds
    telemetry_coverage   FLOAT       NOT NULL DEFAULT 0,  -- fraction of expected telemetry received
    correlation_score    FLOAT       NOT NULL DEFAULT 0,  -- timestamp ordering / cross-format consistency
    detail_json          JSON        NOT NULL,
    created_at           DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES test_runs(id)
) ENGINE=InnoDB;

-- audit_log: immutable audit trail for all simulator actions
CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    actor      VARCHAR(128) NOT NULL DEFAULT 'system',
    action     VARCHAR(128) NOT NULL,
    resource   VARCHAR(256),
    detail     JSON,
    created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- seed pre-built topology devices
INSERT IGNORE INTO devices (id, name, device_type, ip_address, mac_address, os_type, vendor, network_zone, telemetry) VALUES
('d0000001-0000-0000-0000-000000000001','gw-internet','router','203.0.113.1','00:11:22:33:44:01','IOS 16.9','Cisco','external','{"syslog":true,"netflow":true,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000002','fw-perimeter','firewall','10.0.0.1','00:11:22:33:44:02','FortiOS 7.4','Fortinet','dmz','{"syslog":true,"netflow":true,"sflow":false,"pcap":true}'),
('d0000001-0000-0000-0000-000000000003','sw-core','switch','10.0.1.1','00:11:22:33:44:03','EOS 4.27','Arista','internal','{"syslog":true,"netflow":false,"sflow":true,"pcap":false}'),
('d0000001-0000-0000-0000-000000000004','sw-dmz','switch','10.0.2.1','00:11:22:33:44:04','EOS 4.27','Arista','dmz','{"syslog":true,"netflow":false,"sflow":true,"pcap":false}'),
('d0000001-0000-0000-0000-000000000005','dc-primary','server','10.0.1.10','00:11:22:33:44:05','Windows Server 2022','Microsoft','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000006','dc-secondary','server','10.0.1.11','00:11:22:33:44:06','Windows Server 2022','Microsoft','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000007','web-server','server','10.0.2.10','00:11:22:33:44:07','Ubuntu 22.04','Canonical','dmz','{"syslog":true,"netflow":false,"sflow":false,"pcap":true}'),
('d0000001-0000-0000-0000-000000000008','db-server','server','10.0.1.20','00:11:22:33:44:08','RHEL 9','Red Hat','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000009','file-server','server','10.0.1.21','00:11:22:33:44:09','Windows Server 2019','Microsoft','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000010','mail-server','server','10.0.2.11','00:11:22:33:44:0a','Ubuntu 22.04','Canonical','dmz','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000011','ws-finance-01','workstation','10.0.3.101','00:11:22:33:44:11','Windows 11','Microsoft','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000012','ws-finance-02','workstation','10.0.3.102','00:11:22:33:44:12','Windows 11','Microsoft','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000013','ws-hr-01','workstation','10.0.3.103','00:11:22:33:44:13','Windows 10','Microsoft','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000014','ws-dev-01','workstation','10.0.3.104','00:11:22:33:44:14','Ubuntu 22.04','Canonical','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000015','laptop-mgr-01','workstation','10.0.3.105','00:11:22:33:44:15','macOS 14','Apple','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000016','ap-floor1','wireless_ap','10.0.4.1','00:11:22:33:44:16','AireOS 8.10','Cisco','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000017','ap-floor2','wireless_ap','10.0.4.2','00:11:22:33:44:17','AireOS 8.10','Cisco','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000018','dns-server','server','10.0.1.53','00:11:22:33:44:18','Ubuntu 22.04','Canonical','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":true}'),
('d0000001-0000-0000-0000-000000000019','ntp-server','server','10.0.1.123','00:11:22:33:44:19','Ubuntu 22.04','Canonical','internal','{"syslog":true,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000020','iot-camera-01','iot','10.0.5.1','00:11:22:33:44:20','Embedded Linux','Hikvision','internal','{"syslog":false,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000021','iot-hvac','iot','10.0.5.2','00:11:22:33:44:21','Embedded RTOS','Honeywell','internal','{"syslog":false,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000022','attacker-ext','workstation','198.51.100.100','00:aa:bb:cc:dd:01','Kali Linux 2024','Offensive','external','{"syslog":false,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000023','c2-server','server','198.51.100.200','00:aa:bb:cc:dd:02','Ubuntu 22.04','Unknown','external','{"syslog":false,"netflow":false,"sflow":false,"pcap":false}'),
('d0000001-0000-0000-0000-000000000024','vpn-gateway','router','10.0.0.2','00:11:22:33:44:24','FortiOS 7.4','Fortinet','dmz','{"syslog":true,"netflow":true,"sflow":false,"pcap":false}');
