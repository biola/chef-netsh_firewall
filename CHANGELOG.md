netsh_firewall Cookbook CHANGELOG
========================
This file is used to list changes made in each version of the netsh_firewall cookbook.

v1.0.0 (2018-01-19)
--------------------
- Refactored code to use Chef custom resources. Chef Client 12.5 or higher is now required to use this cookbook.
- Local/remote IP and port properties for the `netsh_firewall_rule` resource now accept arrays as well as strings and will automatically sort values for stable ordering

v0.3.2 (2016-01-19)
--------------------
- Fixed ICMP rules not working due to default values for localport and remoteport
