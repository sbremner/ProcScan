# ProcScan
Scan all active processes looking for anomalies. To add custom rules, add to ProcRules.cpp a new `RULE_FUNCTION` and then add that to the list of rules to run in the `RunRules` function at the bottom of the cpp file.

## Usage
Simply run the tool on a suspect system. If you would like to inspect all processes, must be run as administrator.
