#!/usr/bin/env python3
"""
StarlingX Cluster Health Check Script
Monitors Wind River StarlingX cluster health including connectivity, storage, K8s, and applications

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
from datetime import datetime
from typing import Dict, List, Tuple
import paramiko
import getpass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

class StarlingXHealthCheck:
    """
    Main health check class for StarlingX clusters
    Performs comprehensive health monitoring of distributed cloud systems
    """
    
    def __init__(self, host_ip: str, username: str = "sysadmin", password: str = None, key_path: str = None):
        """
        Initialize health checker with connection parameters
        
        Args:
            host_ip: IP address of StarlingX system controller
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
        Establish SSH connection to the StarlingX host
        
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
    
    def check_host_reachability(self) -> Dict:
        """
        Check if the StarlingX host is reachable via ping and SSH
        
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
        
        # Get overall Ceph cluster status in JSON format
        stdout, stderr, code = self.execute_command('sudo ceph status --format json')
        if code == 0:
            try:
                ceph_status = json.loads(stdout)
                # Extract key health indicators
                result['details']['cluster_status'] = ceph_status.get('health', {}).get('status', 'UNKNOWN')
                result['details']['mon_status'] = len(ceph_status.get('monmap', {}).get('mons', []))
                result['details']['osd_status'] = ceph_status.get('osdmap', {}).get('osdmap', {})
            except:
                result['details']['cluster_status'] = 'PARSE_ERROR'
        
        # Get detailed OSD (Object Storage Daemon) status
        stdout, stderr, code = self.execute_command('sudo ceph osd status')
        if code == 0:
            result['details']['osd_details'] = stdout.strip()
        
        # Get storage usage statistics
        stdout, stderr, code = self.execute_command('sudo ceph df')
        if code == 0:
            result['details']['storage_usage'] = stdout.strip()
        
        # Determine overall health: HEALTH_OK means everything is good
        result['status'] = 'HEALTHY' if result['details'].get('cluster_status') == 'HEALTH_OK' else 'WARNING'
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
        
        # Check StarlingX platform pods in armada namespace
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
        Check StarlingX platform services and applications
        Identifies failed services, active alarms, and application issues
        
        Returns:
            Dict with StarlingX service health details
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
        
        # Get disk usage for all mounted filesystems
        stdout, stderr, code = self.execute_command('df -h')
        if code == 0:
            result['details']['disk_usage'] = stdout.strip()
        
        # Get system load average (1, 5, 15 minute averages)
        stdout, stderr, code = self.execute_command('uptime')
        if code == 0:
            result['details']['load_average'] = stdout.strip()
        
        # For now, assume resources are healthy (could add thresholds later)
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
        
        # Get all network interfaces and their IP addresses
        stdout, stderr, code = self.execute_command('ip addr show')
        if code == 0:
            result['details']['interfaces'] = stdout.strip()
        
        # Get routing table to verify network paths
        stdout, stderr, code = self.execute_command('ip route')
        if code == 0:
            result['details']['routes'] = stdout.strip()
        
        # Network is assumed healthy if commands execute (could add connectivity tests)
        result['status'] = 'HEALTHY'
        return result
    
    def check_installed_software(self) -> Dict:
        """
        Check installed Wind River StarlingX software versions
        Verifies platform packages and container runtime
        
        Returns:
            Dict with software version and package details
        """
        result = {'status': 'UNKNOWN', 'details': {}}
        
        # Get StarlingX build information and version
        stdout, stderr, code = self.execute_command('cat /etc/build.info')
        if code == 0:
            result['details']['build_info'] = stdout.strip()
        
        # List all StarlingX and Wind River related packages
        stdout, stderr, code = self.execute_command('rpm -qa | grep -E "(wind|starling|platform)" | sort')
        if code == 0:
            result['details']['starlingx_packages'] = stdout.strip()
        
        # Check container runtime version (Docker or Containerd)
        stdout, stderr, code = self.execute_command('docker version --format "{{.Server.Version}}" 2>/dev/null || containerd --version')
        if code == 0:
            result['details']['container_runtime'] = stdout.strip()
        
        # Software check is informational, always healthy
        result['status'] = 'HEALTHY'
        return result
    
    def run_health_check(self) -> Dict:
        """
        Execute complete health check sequence
        Runs all health check modules and collects results
        
        Returns:
            Dict containing all health check results
        """
        rprint(f"[bold blue]Starting StarlingX Health Check for {self.host_ip}[/bold blue]")
        rprint(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Define all health check modules to run
        checks = [
            ("Host Reachability", self.check_host_reachability),      # Basic connectivity
            ("Ceph Storage", self.check_ceph_storage),                # Storage cluster health
            ("Kubernetes Cluster", self.check_kubernetes_cluster),    # K8s and pod health
            ("StarlingX Services", self.check_starlingx_services),    # Platform services
            ("Subclouds", self.check_subclouds),                      # Distributed cloud
            ("System Resources", self.check_system_resources),        # CPU/Memory/Disk
            ("Network Connectivity", self.check_network_connectivity), # Network config
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
        table = Table(title="StarlingX Cluster Health Check Results")
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
    
    def save_report(self, filename: str = None):
        """
        Save detailed health check report to JSON file
        Creates timestamped report with all collected data
        
        Args:
            filename: Optional custom filename, auto-generated if not provided
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"C:\\Users\\mshokr\\Documents\\code\\health_check\\starlingx_health_report_{timestamp}.json"
        
        # Create comprehensive report structure
        report = {
            'timestamp': datetime.now().isoformat(),
            'host': self.host_ip,
            'results': self.results
        }
        
        # Write report to file
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        rprint(f"[green]Report saved to: {filename}[/green]")
    
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
    health_checker = StarlingXHealthCheck(host_ip, username, password, key_path)
    
    try:
        # Execute the complete health check sequence
        health_checker.run_health_check()
        health_checker.display_results()
        health_checker.save_report()
    except KeyboardInterrupt:
        print("\nHealth check interrupted by user")
    except Exception as e:
        print(f"Error during health check: {e}")
    finally:
        # Always clean up resources
        health_checker.cleanup()

if __name__ == "__main__":
    main()
