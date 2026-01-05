#!/usr/bin/env python3
"""
Cloud Cluster Health Check Script
Monitors Wind River Cloud cluster health including connectivity, storage, K8s, and applications

Usage:
    python starlingx_health_check.py <host_ip> [username] [--key-path /path/to/key]
    
Examples:
    python starlingx_health_check.py 192.168.1.100
    python starlingx_health_check.py 192.168.1.100 sysadmin --key-path ~/.ssh/id_rsa
"""

import subprocess
import socket
import json
import sys
import os
import webbrowser
from datetime import datetime
from typing import Dict, List, Tuple
import paramiko
import getpass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

class CloudHealthCheck:
    """
    Main health check class for Cloud clusters
    Performs comprehensive health monitoring of distributed cloud systems
    """
    
    def __init__(self, host_ip: str, username: str = "sysadmin", password: str = None, key_path: str = None):
        """
        Initialize health checker with connection parameters
        
        Args:
            host_ip: IP address of Cloud system controller
            username: SSH username (default: sysadmin)
            password: SSH password (prompted if not provided)
            key_path: Path to SSH private key (optional)
        """
        self.host_ip = host_ip
        self.username = username
        self.password = password
        self.key_path = key_path
        self.ssh_client = None
        self.console = Console()
        self.results = {}  # Store all health check results
        
    def connect_ssh(self) -> bool:
        """
        Establish SSH connection to the Cloud host
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.ssh_client = paramiko.SSHClient()
            # Accept unknown host keys (for lab environments)
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try SSH key authentication first, then password
            if self.key_path:
                self.ssh_client.connect(self.host_ip, username=self.username, key_filename=self.key_path)
            else:
                self.ssh_client.connect(self.host_ip, username=self.username, password=self.password)
            return True
        except Exception as e:
            self.results['ssh_connection'] = {'status': 'FAILED', 'error': str(e)}
            return False
    
    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """
        Execute command via SSH on the remote host
        
        Args:
            command: Shell command to execute
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not self.ssh_client:
            return "", "No SSH connection", 1
        
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            return stdout.read().decode(), stderr.read().decode(), stdout.channel.recv_exit_status()
        except Exception as e:
            return "", str(e), 1
    
    def get_cluster_info(self) -> Dict:
        """
        Get comprehensive cluster information from system show command
        
        Returns:
            Dict with all system details
        """
        cluster_info = {
            'name': 'Unknown',
            'system_type': 'Unknown', 
            'system_mode': 'Unknown',
            'timezone': 'Unknown',
            'description': 'Unknown'
        }
        
        # Ensure SSH connection exists
        if not self.ssh_client:
            self.connect_ssh()
        
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system show')
        if code == 0:
            lines = stdout.strip().split('\n')
            for line in lines:
                line = line.strip()
                if '| name ' in line and '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        cluster_info['name'] = parts[2]
                elif '| system_type ' in line and '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        cluster_info['system_type'] = parts[2]
                elif '| system_mode ' in line and '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        cluster_info['system_mode'] = parts[2]
                elif '| timezone ' in line and '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        cluster_info['timezone'] = parts[2]
                elif '| description ' in line and '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        cluster_info['description'] = parts[2]
        
        return cluster_info
    
    def check_host_reachability(self) -> Dict:
        """
        Check if the Cloud host is reachable via ping and SSH
        
        Returns:
            Dict with ping/ssh status and overall reachability
        """
        result = {'status': 'UNKNOWN', 'ping': False, 'ssh': False}
        
        # Test network connectivity with ping
        try:
            response = subprocess.run(['ping', '-n', '3', self.host_ip], 
                                    capture_output=True, text=True, timeout=10)
            result['ping'] = response.returncode == 0
        except:
            result['ping'] = False
        
        # Test SSH connectivity
        result['ssh'] = self.connect_ssh()
        
        # Overall status: both ping and SSH must work
        result['status'] = 'HEALTHY' if result['ping'] and result['ssh'] else 'FAILED'
        
        return result
    
    def check_ceph_storage(self) -> Dict:
        """
        Check Ceph distributed storage cluster health
        Monitors cluster status, OSD health, and storage usage
        
        Returns:
            Dict with Ceph cluster health details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get Ceph health status
        stdout, stderr, code = self.execute_command('ceph health')
        if code == 0:
            result['details']['health'] = stdout.strip()
            is_healthy = 'HEALTH_OK' in stdout
        else:
            result['details']['health'] = f'Command failed: {stderr.strip()}'
            is_healthy = False
        
        # Get overall Ceph status
        stdout, stderr, code = self.execute_command('ceph status')
        if code == 0:
            result['details']['status'] = stdout.strip()
        else:
            result['details']['status'] = f'Command failed: {stderr.strip()}'
        
        # Get monitor status
        stdout, stderr, code = self.execute_command('ceph mon stat')
        if code == 0:
            result['details']['mon_stat'] = stdout.strip()
        else:
            result['details']['mon_stat'] = f'Command failed: {stderr.strip()}'
        
        # Get storage usage
        stdout, stderr, code = self.execute_command('ceph df')
        if code == 0:
            result['details']['df'] = stdout.strip()
        else:
            result['details']['df'] = f'Command failed: {stderr.strip()}'
        
        # Get OSD tree
        stdout, stderr, code = self.execute_command('ceph osd tree')
        if code == 0:
            result['details']['osd_tree'] = stdout.strip()
        else:
            result['details']['osd_tree'] = f'Command failed: {stderr.strip()}'
        
        # Get OSD status
        stdout, stderr, code = self.execute_command('ceph osd status')
        if code == 0:
            result['details']['osd_status'] = stdout.strip()
        else:
            result['details']['osd_status'] = f'Command failed: {stderr.strip()}'
        
        # Get placement group status
        stdout, stderr, code = self.execute_command('ceph pg stat')
        if code == 0:
            result['details']['pg_stat'] = stdout.strip()
        else:
            result['details']['pg_stat'] = f'Command failed: {stderr.strip()}'
        
        # Check if Ceph is available at all
        if 'Command failed' in result['details']['health']:
            result['status'] = 'FAILED'
            result['details']['note'] = 'Ceph may not be installed or accessible'
        else:
            result['status'] = 'HEALTHY' if is_healthy else 'WARNING'
        
        return result
    
    def check_kubernetes_cluster(self) -> Dict:
        """
        Check Kubernetes cluster health and identify problematic pods
        Focuses on node readiness and unhealthy pod detection
        
        Returns:
            Dict with K8s cluster health and problem details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get all Kubernetes nodes and their status
        stdout, stderr, code = self.execute_command('kubectl get nodes -o json')
        if code == 0:
            try:
                nodes = json.loads(stdout)
                result['details']['nodes'] = []
                for node in nodes.get('items', []):
                    # Check if node is in Ready state
                    node_info = {
                        'name': node['metadata']['name'],
                        'status': 'Ready' if any(c['type'] == 'Ready' and c['status'] == 'True' 
                                               for c in node['status']['conditions']) else 'NotReady',
                        'version': node['status']['nodeInfo']['kubeletVersion']
                    }
                    result['details']['nodes'].append(node_info)
            except:
                result['details']['nodes'] = 'PARSE_ERROR'
        
        # Find pods that are NOT in Running or Succeeded state (these are problems)
        stdout, stderr, code = self.execute_command('kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded -o wide')
        result['details']['unhealthy_pods'] = stdout.strip() if stdout.strip() else 'All pods healthy'
        
        # Specifically check system pods for common failure states
        stdout, stderr, code = self.execute_command('kubectl get pods -n kube-system -o wide | grep -E "(Error|CrashLoopBackOff|Pending|ImagePullBackOff|ContainerCreating)"')
        result['details']['system_pod_issues'] = stdout.strip() if stdout.strip() else 'All system pods healthy'
        
        # Check Cloud platform pods in armada namespace
        stdout, stderr, code = self.execute_command('kubectl get pods -n armada -o wide')
        if code == 0:
            result['details']['platform_pods'] = stdout.strip()
        
        # Determine overall health status
        ready_nodes = sum(1 for n in result['details'].get('nodes', []) if n.get('status') == 'Ready')
        total_nodes = len(result['details'].get('nodes', []))
        has_unhealthy_pods = 'All pods healthy' not in result['details'].get('unhealthy_pods', '')
        has_system_issues = 'All system pods healthy' not in result['details'].get('system_pod_issues', '')
        
        # Status is WARNING if any nodes are down OR any pods are unhealthy
        result['status'] = 'WARNING' if (ready_nodes != total_nodes or has_unhealthy_pods or has_system_issues) else 'HEALTHY'
        return result
    
    def check_starlingx_services(self) -> Dict:
        """
        Check Cloud platform services and applications
        Identifies failed services, active alarms, and application issues
        
        Returns:
            Dict with Cloud service health details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get list of all hosts in the system
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system host-list')
        if code == 0:
            result['details']['hosts'] = stdout.strip()
        
        # Look specifically for failed or disabled services (these are problems)
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system service-list | grep -E "(disabled|failed)"')
        result['details']['failed_services'] = stdout.strip() if stdout.strip() else 'All services healthy'
        
        # Get complete service list for reference
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system service-list')
        if code == 0:
            result['details']['all_services'] = stdout.strip()
        
        # Check for active alarms (these indicate system issues)
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && fm alarm-list')
        if code == 0:
            result['details']['alarms'] = stdout.strip() if stdout.strip() else 'No active alarms'
        
        # Check platform applications that are not in 'applied' state
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system application-list | grep -v "applied"')
        result['details']['app_issues'] = stdout.strip() if stdout.strip() else 'All applications applied'
        
        # Determine overall health based on service failures, alarms, and app issues
        has_failed_services = 'All services healthy' not in result['details'].get('failed_services', '')
        has_alarms = 'No active alarms' not in result['details'].get('alarms', '')
        has_app_issues = 'All applications applied' not in result['details'].get('app_issues', '')
        
        # Status is WARNING if any services failed OR alarms exist OR apps have issues
        result['status'] = 'WARNING' if (has_failed_services or has_alarms or has_app_issues) else 'HEALTHY'
        return result
    
    def check_subclouds(self) -> Dict:
        """
        Check all subclouds in a distributed cloud deployment
        Monitors subcloud status, sync state, and individual health
        
        Returns:
            Dict with subcloud health and sync status
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get list of all subclouds managed by this system controller
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && dcmanager subcloud list')
        if code == 0:
            result['details']['subcloud_list'] = stdout.strip()
            
            # Parse subcloud names from the table output
            subclouds = []
            lines = stdout.strip().split('\n')
            for line in lines[3:]:  # Skip header lines (usually first 3 lines)
                if '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    # Extract subcloud name from second column
                    if len(parts) > 2 and parts[1] and parts[1] != 'name':
                        subclouds.append(parts[1])
            
            # Check detailed status for each individual subcloud
            subcloud_details = {}
            for subcloud in subclouds:
                # Get detailed subcloud information
                stdout, stderr, code = self.execute_command(f'source /etc/platform/openrc && dcmanager subcloud show {subcloud}')
                if code == 0:
                    subcloud_details[subcloud] = stdout.strip()
                
                # Check for alarms specific to this subcloud
                stdout, stderr, code = self.execute_command(f'source /etc/platform/openrc && dcmanager alarm summary {subcloud}')
                if code == 0:
                    subcloud_details[f'{subcloud}_alarms'] = stdout.strip()
            
            result['details']['individual_subclouds'] = subcloud_details
        else:
            # This might not be a system controller or no subclouds exist
            result['details']['subcloud_list'] = 'No subclouds found or not a system controller'
        
        # Get detailed sync status for all subclouds
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && dcmanager subcloud list --detail')
        if code == 0:
            result['details']['sync_status'] = stdout.strip()
        
        # Determine overall subcloud health
        if 'managed' in result['details'].get('subcloud_list', ''):
            # Count subclouds in 'managed' state (healthy) vs total
            healthy_count = result['details']['subcloud_list'].count('managed')
            total_count = result['details']['subcloud_list'].count('\n') - 3  # Subtract header lines
            result['status'] = 'HEALTHY' if healthy_count == total_count and total_count > 0 else 'WARNING'
        else:
            # No subclouds or not a system controller - this is normal for edge sites
            result['status'] = 'HEALTHY'
        
        return result
    
    def check_system_resources(self) -> Dict:
        """
        Check system resource utilization (CPU, Memory, Disk)
        Monitors basic system health indicators
        
        Returns:
            Dict with system resource usage details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get current CPU usage percentage
        stdout, stderr, code = self.execute_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1")
        if code == 0:
            result['details']['cpu_usage'] = stdout.strip() + '%'
        
        # Get memory usage in human-readable format
        stdout, stderr, code = self.execute_command('free -h')
        if code == 0:
            result['details']['memory'] = stdout.strip()
        
        # Check disk usage - only show partitions above 75%
        stdout, stderr, code = self.execute_command("df -h | awk 'NR>1 {gsub(/%/, \"\", $5); if($5 > 75) print $0}'")
        if code == 0 and stdout.strip():
            result['details']['high_disk_usage'] = stdout.strip()
            result['status'] = 'WARNING'
        else:
            result['details']['high_disk_usage'] = 'All partitions below 75% usage'
            result['status'] = 'HEALTHY'
        
        # Get system load average (1, 5, 15 minute averages)
        stdout, stderr, code = self.execute_command('uptime')
        if code == 0:
            result['details']['load_average'] = stdout.strip()
        
        return result
    
    def check_wind_river_analytics(self) -> Dict:
        """
        Check Wind River Analytics service status
        Monitors analytics components and data collection
        
        Returns:
            Dict with Wind River Analytics status details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Check if monitor namespace exists
        stdout, stderr, code = self.execute_command('kubectl get namespace monitor')
        if code == 0:
            result['details']['monitor_namespace'] = 'Monitor namespace exists'
            
            # Get all pods in monitor namespace with detailed status
            stdout, stderr, code = self.execute_command('kubectl get pods -n monitor -o wide')
            if code == 0:
                result['details']['monitor_pods'] = stdout.strip()
                
                # Check for unhealthy pods in monitor namespace
                stdout, stderr, code = self.execute_command('kubectl get pods -n monitor --field-selector=status.phase!=Running,status.phase!=Succeeded')
                if code == 0 and stdout.strip():
                    result['details']['monitor_pod_issues'] = stdout.strip()
                else:
                    result['details']['monitor_pod_issues'] = 'All monitor pods healthy'
                
                # Get pod resource usage in monitor namespace
                stdout, stderr, code = self.execute_command('kubectl top pods -n monitor --no-headers 2>/dev/null')
                if code == 0 and stdout.strip():
                    result['details']['monitor_pod_resources'] = stdout.strip()
            
            result['status'] = 'HEALTHY'
        else:
            result['details']['monitor_namespace'] = 'Monitor namespace not found - Wind River Analytics may not be installed'
            
            # Check analytics pods in analytics namespace as fallback
            stdout, stderr, code = self.execute_command('kubectl get pods -n analytics -o wide')
            if code == 0:
                result['details']['analytics_pods'] = stdout.strip()
                result['status'] = 'WARNING'
            else:
                result['details']['analytics_pods'] = 'Analytics namespace not found'
                result['status'] = 'FAILED'
        
        return result
    
    def check_system_uptime(self) -> Dict:
        """
        Check system uptime for main cloud and all subclouds
        Shows how long systems have been running
        
        Returns:
            Dict with uptime information for all systems
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get main system uptime
        stdout, stderr, code = self.execute_command('uptime')
        if code == 0:
            result['details']['main_system_uptime'] = stdout.strip()
        
        # Get subclouds list and their uptime
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && dcmanager subcloud list --format value --column name')
        if code == 0 and stdout.strip():
            subclouds = [sc.strip() for sc in stdout.strip().split('\n') if sc.strip()]
            subcloud_uptimes = {}
            
            for subcloud in subclouds:
                # Try to get uptime from each subcloud
                stdout, stderr, code = self.execute_command(f'source /etc/platform/openrc && dcmanager subcloud show {subcloud} --format value --column management-state,availability-status')
                if code == 0:
                    subcloud_uptimes[f'{subcloud}_status'] = stdout.strip()
            
            result['details']['subclouds_status'] = subcloud_uptimes if subcloud_uptimes else 'No subclouds found'
        else:
            result['details']['subclouds_status'] = 'No subclouds found or not a system controller'
        
        result['status'] = 'HEALTHY'
        return result
    
    def check_network_connectivity(self) -> Dict:
        """
        Check network interfaces and routing configuration
        Verifies network setup and connectivity paths
        
        Returns:
            Dict with network interface and routing details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get primary network interfaces with IP addresses
        stdout, stderr, code = self.execute_command('ip addr show | grep -A 3 -E "^[0-9]+: (eth|ens|enp|eno)" | grep -E "(^[0-9]+:|inet )"')
        if code == 0:
            result['details']['primary_interfaces'] = stdout.strip()
        
        # Check for packet drops on network interfaces
        stdout, stderr, code = self.execute_command('cat /proc/net/dev | awk "NR>2 && ($4>0 || $12>0) {print $1, \"RX drops:\", $4, \"TX drops:\", $12}"')
        if code == 0 and stdout.strip():
            result['details']['packet_drops'] = stdout.strip()
        else:
            result['details']['packet_drops'] = 'No packet drops detected'
        
        # Get routing table to verify network paths
        stdout, stderr, code = self.execute_command('ip route')
        if code == 0:
            result['details']['routes'] = stdout.strip()
        
        result['status'] = 'HEALTHY'
        return result
    
    def check_installed_software(self) -> Dict:
        """
        Check installed Wind River Cloud software versions
        Verifies platform packages and container runtime
        
        Returns:
            Dict with software version and package details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get Cloud build information and version
        stdout, stderr, code = self.execute_command('cat /etc/build.info')
        if code == 0:
            result['details']['build_info'] = stdout.strip()
        
        # List all Cloud and Wind River related packages
        stdout, stderr, code = self.execute_command('rpm -qa | grep -E "(wind|starling|platform)" | sort')
        if code == 0:
            result['details']['cloud_packages'] = stdout.strip()
        
        # Check container runtime version (Docker or Containerd)
        stdout, stderr, code = self.execute_command('docker version --format "{{.Server.Version}}" 2>/dev/null || containerd --version')
        if code == 0:
            result['details']['container_runtime'] = stdout.strip()
        
        # Get application list
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system application-list')
        if code == 0:
            result['details']['application_list'] = stdout.strip()
        
        # Get analytics application details
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system application-show wr-analytics')
        if code == 0:
            result['details']['analytics_app'] = stdout.strip()
        
        # Get system inventory
        stdout, stderr, code = self.execute_command('source /etc/platform/openrc && system inventory-list')
        if code == 0:
            result['details']['inventory_list'] = stdout.strip()
        
        # Get non-running services
        stdout, stderr, code = self.execute_command('systemctl list-units --type=service | grep -v running')
        if code == 0:
            result['details']['non_running_services'] = stdout.strip()
        
        result['status'] = 'HEALTHY'
        return result
    
    def run_health_check(self) -> Dict:
        """
        Execute complete health check sequence
        Runs all health check modules and collects results
        
        Returns:
            Dict containing all health check results
        """
        # Get cluster info first
        cluster_info = self.get_cluster_info()
        
        rprint(f"[bold blue]Starting Cloud Health Check for {self.host_ip}[/bold blue]")
        rprint(f"System: {cluster_info['name']} | Type: {cluster_info['system_type']} | Mode: {cluster_info['system_mode']}")
        rprint(f"Timezone: {cluster_info['timezone']} | Description: {cluster_info['description']}")
        rprint(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Store cluster info for HTML report
        self.cluster_info = cluster_info
        
        # Define all health check modules to run
        checks = [
            ("Host Reachability", self.check_host_reachability),      # Basic connectivity
            ("Ceph Storage", self.check_ceph_storage),                # Storage cluster health
            ("Kubernetes Cluster", self.check_kubernetes_cluster),    # K8s and pod health
            ("Cloud Services", self.check_starlingx_services),        # Platform services
            ("Subclouds", self.check_subclouds),                      # Distributed cloud
            ("System Resources", self.check_system_resources),        # CPU/Memory/Disk
            ("System Uptime", self.check_system_uptime),              # Uptime for all systems
            ("Network Connectivity", self.check_network_connectivity), # Network config
            ("Wind River Analytics", self.check_wind_river_analytics), # Analytics status
            ("Installed Software", self.check_installed_software),    # Software versions
        ]
        
        # Execute each health check module
        for check_name, check_func in checks:
            rprint(f"[yellow]Checking {check_name}...[/yellow]")
            self.results[check_name.lower().replace(' ', '_')] = check_func()
        
        return self.results
    
    def display_results(self):
        """
        Display health check results in a formatted table
        Shows component status with color coding and summary
        """
        table = Table(title="Cloud Cluster Health Check Results")
        table.add_column("Component", style="cyan", no_wrap=True)
        table.add_column("Status", style="magenta")
        table.add_column("Details", style="green")
        
        # Define status colors for visual clarity
        status_colors = {
            'HEALTHY': '[green]✓ HEALTHY[/green]',
            'WARNING': '[yellow]⚠ WARNING[/yellow]',
            'FAILED': '[red]✗ FAILED[/red]',
            'UNKNOWN': '[gray]? UNKNOWN[/gray]'
        }
        
        # Add each component result to the table
        for component, data in self.results.items():
            status = data.get('status', 'UNKNOWN')
            colored_status = status_colors.get(status, status)
            
            # Format details for display (truncate if too long)
            details = data.get('details', {})
            if isinstance(details, dict):
                detail_str = '\n'.join([f"{k}: {v}" for k, v in details.items() if isinstance(v, str)])[:100]
            else:
                detail_str = str(details)[:100]
            
            table.add_row(
                component.replace('_', ' ').title(),
                colored_status,
                detail_str + "..." if len(detail_str) > 97 else detail_str
            )
        
        self.console.print(table)
        
        # Display overall health summary
        healthy = sum(1 for r in self.results.values() if r.get('status') == 'HEALTHY')
        total = len(self.results)
        
        # Color code the summary based on health percentage
        summary_color = 'green' if healthy == total else 'yellow' if healthy > total/2 else 'red'
        self.console.print(f"\n[{summary_color}]Summary: {healthy}/{total} components healthy[/{summary_color}]")
    
    def save_html_report(self, filename: str = None):
        """
        Save detailed health check report to HTML file in Downloads directory
        Creates timestamped report with all collected data
        
        Args:
            filename: Optional custom filename, auto-generated if not provided
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
            filename = os.path.join(downloads_path, f"cloud_health_report_{timestamp}.html")
        
        # Generate HTML report
        html_content = self._generate_html_report()
        
        # Write report to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        rprint(f"[green]HTML Report saved to: {filename}[/green]")
        
        # Open the HTML file in default browser
        webbrowser.open(f'file://{filename}')
        return filename
    
    def _generate_html_report(self) -> str:
        """
        Generate HTML content for the health check report
        
        Returns:
            String containing complete HTML report
        """
        status_colors = {
            'HEALTHY': '#28a745',
            'WARNING': '#ffc107', 
            'FAILED': '#dc3545',
            'UNKNOWN': '#6c757d'
        }
        
        status_icons = {
            'HEALTHY': '✓',
            'WARNING': '⚠',
            'FAILED': '✗',
            'UNKNOWN': '?'
        }
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Health Check Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }}
        .header {{ background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary {{ background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .component {{ background: white; margin: 10px 0; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .status {{ font-weight: bold; padding: 5px 10px; border-radius: 4px; color: white; }}
        .details {{ margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 4px; font-family: monospace; white-space: pre-wrap; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Cloud Health Check Report</h1>
        <p><strong>System Name:</strong> {getattr(self, 'cluster_info', {}).get('name', 'Unknown')}</p>
        <p><strong>System Type:</strong> {getattr(self, 'cluster_info', {}).get('system_type', 'Unknown')} | <strong>Mode:</strong> {getattr(self, 'cluster_info', {}).get('system_mode', 'Unknown')}</p>
        <p><strong>Timezone:</strong> {getattr(self, 'cluster_info', {}).get('timezone', 'Unknown')}</p>
        <p><strong>Description:</strong> {getattr(self, 'cluster_info', {}).get('description', 'Unknown')}</p>
        <p><strong>Host IP:</strong> {self.host_ip} | <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""
        
        # Add summary
        healthy = sum(1 for r in self.results.values() if r.get('status') == 'HEALTHY')
        total = len(self.results)
        summary_color = '#28a745' if healthy == total else '#ffc107' if healthy > total/2 else '#dc3545'
        
        html += f"""
    <div class="summary">
        <h2>Summary</h2>
        <p style="color: {summary_color}; font-size: 18px; font-weight: bold;">
            {healthy}/{total} components healthy
        </p>
    </div>
"""
        
        # Define the order of components in HTML report
        component_order = [
            'wrcp_cluster_info',
            'ceph_storage',
            'kubernetes_cluster',
            'cloud_services',
            'subclouds',
            'system_resources',
            'network_connectivity',
            'wind_river_analytics',
            'installed_software',
            'system_uptime',
            'host_reachability'
        ]
        
        # Add component details in specified order
        for component_key in component_order:
            if component_key in self.results:
                data = self.results[component_key]
                status = data.get('status', 'UNKNOWN')
                color = status_colors.get(status, '#6c757d')
                icon = status_icons.get(status, '?')
                
                html += f"""
    <div class="component">
        <h3>{component_key.replace('_', ' ').title()}</h3>
        <span class="status" style="background-color: {color};">{icon} {status}</span>
        <div class="details">
"""
                
                details = data.get('details', {})
                if isinstance(details, dict):
                    for key, value in details.items():
                        if isinstance(value, str):
                            html += f"<strong>{key.replace('_', ' ').title()}:</strong>\n{value}\n\n"
                else:
                    html += str(details)
                
                html += "</div></div>"
        
        html += """
</body>
</html>
"""
        return html
    
    def cleanup(self):
        """
        Clean up resources and close SSH connection
        Should be called when health check is complete
        """
        if self.ssh_client:
            self.ssh_client.close()

def main():
    """
    Main function - handles command line arguments and orchestrates health check
    
    Command line usage:
        python starlingx_health_check.py <host_ip> [username] [--key-path /path/to/key]
    """
    if len(sys.argv) < 2:
        print("Usage: python starlingx_health_check.py <host_ip> [username] [--key-path /path/to/key]")
        sys.exit(1)
    
    # Parse command line arguments
    host_ip = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "sysadmin"
    
    # Check for optional SSH key authentication
    key_path = None
    if "--key-path" in sys.argv:
        key_index = sys.argv.index("--key-path")
        if key_index + 1 < len(sys.argv):
            key_path = sys.argv[key_index + 1]
    
    # Get password if no SSH key provided (primary authentication method)
    password = None
    if not key_path:
        password = getpass.getpass(f"Enter password for {username}@{host_ip}: ")
    
    # Create and run health checker
    health_checker = CloudHealthCheck(host_ip, username, password, key_path)
    
    try:
        # Execute the complete health check sequence
        health_checker.run_health_check()
        health_checker.display_results()
        health_checker.save_html_report()
    except KeyboardInterrupt:
        print("\nHealth check interrupted by user")
    except Exception as e:
        print(f"Error during health check: {e}")
    finally:
        # Always clean up resources
        health_checker.cleanup()

if __name__ == "__main__":
    main()
