# Ingestion patterns (moved)

Direct SDL ingestion (`uploadLogs`, `addEvents`) has been removed from this skill. Ingest raw logs/events via the **HEC ingest** path (HTTP Event Collector on the ingest host, with a named `parser`). UAM alert/indicator creation lives in `sentinelone-mgmt-console-api` (`uam_*`). This skill covers queries and configuration files only.
