# -*- coding: utf-8 -*-
"""
Middleware detector package
===========================
Each module under this package is expected to export a
`detect(prompt: str) -> dict` function. The gateway scans and registers
them automatically at startup.

Fields in the dict returned by detect:
  - is_malicious (bool) : whether classified as malicious, required
  - reason       (str)  : reason for the hit, optional
  - other custom fields : e.g. the specific rule matched, confidence, optional
"""
