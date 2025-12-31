# StarlingX Health Check Configuration Example

# Example usage:
# python starlingx_health_check.py 192.168.1.100
# python starlingx_health_check.py 192.168.1.100 sysadmin
# python starlingx_health_check.py 192.168.1.100 sysadmin --key-path /path/to/ssh/key

# Installation:
# pip install -r requirements.txt

# Authentication:
# - Primary: Password (prompted securely)
# - Optional: SSH key with --key-path flag

# The script checks:
# 1. Host Reachability (ping + SSH)
# 2. Ceph Storage Status
# 3. Kubernetes Cluster Health
# 4. StarlingX Services
# 5. Subclouds (Distributed Cloud)
# 6. System Resources (CPU, Memory, Disk)
# 7. Network Connectivity
# 8. Installed Software Versions

# Output:
# - Colored console output with status table
# - JSON report saved automatically
# - Summary of healthy vs total components
