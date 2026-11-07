# Rule catalog

Rules currently ship compiled in internal/scanner/rules.go. Each has an ID, category, severity, deterministic pattern, description, impact and remediation. RS001–RS013 cover download/execution, credential access, dynamic evaluation, decoding, processes, destinations, infrastructure, workflows, agents, secrets and persistence. RS100/RS101 identify npm/Python install entry points; RS200 correlates lifecycle references with credential/network indicators; RS300 represents OSV vulnerability matches. No executable external rule loading is supported.
