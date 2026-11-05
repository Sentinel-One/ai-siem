# Alert 1770000000000000001 - MV-INSIDERTOOL

**FALSE POSITIVE, confirmed.** Based on the MDR note and history entry carried on the alert itself.

## Order of checks

1. Notes (`uam_get_alert`) - MDR: "Investigated. Alert Type EPP, Classification Benign, Action Resolve."
2. History (`uam_get_alert`) - `analystVerdict` moved to `FALSE_POSITIVE`, by MDR.
3. Telemetry review, only after the above.

An MDR or analyst verdict already recorded on an alert takes precedence over the
detection-engine classification, and is overridden only with new evidence that MDR
did not have. There is none here.

The CRITICAL label comes from the Anti Exploitation/Fileless engine and describes the
potential impact of the threat class, not a confirmed outcome. This exact shape (a
CRITICAL Fileless PowerShell/ransomware alert on this endpoint) is the documented
lesson learned: it was once treated as a confirmed true positive on the engine
classification alone, and MDR later resolved it Benign.

## Disposition

Closed as FALSE POSITIVE. Not escalated to the IR bridge. No host action taken; the
endpoint stays in normal operation.

## Query appendix

No PowerQueries were executed: the alert's own notes and history resolved it before
any telemetry pull was warranted.
