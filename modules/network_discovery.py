# modules/network_discovery.py
import subprocess
import json
import ipaddress
import logging
import xml.etree.ElementTree as ET

from modules.base_module import BaseModule
from config import Config

logger = logging.getLogger(__name__)

class NetworkDiscoveryModule(BaseModule):
    def __init__(self, session_id, project_name):
        super().__init__(session_id, project_name)
        self.log_file = self.get_module_log_file_path("network_discovery.log")
        self.output_file_path = self.get_module_output_file_path("network_discovery_nmap_output")
        logger.info(f"NetworkDiscoveryModule initialized. Log file: {self.log_file}, Output file base: {self.output_file_path}")

    def run(self, params):
        target = params.get('target')
        user_command = params.get('user_command', 'N/A')

        if not target:
            error_message = "Network discovery target is missing. Please provide a network (e.g., 192.168.1.0/24) or a single IP address."
            logger.error(error_message)
            return {
                "status": "error",
                "message": error_message,
                "response_for_ui": error_message,
                "user_command": user_command,
                "module_name": "Network Discovery",
                "target": target,
                "ports": None, # Not applicable for discovery
                "structured_results": {},
                "raw_output": error_message,
                "error_output": error_message,
                "exit_code": 1
            }

        # Validate target as IP network or IP address
        is_valid_target = False
        try:
            # Try as a network (e.g., 192.168.1.0/24, 10.0.0.0/8)
            ipaddress.ip_network(target, strict=False) # strict=False allows host bits to be set in network address
            is_valid_target = True
            logger.debug(f"Target '{target}' validated as an IP network.")
        except ValueError:
            try:
                # Try as a single IP address (e.g., 192.168.1.1)
                ipaddress.ip_address(target)
                is_valid_target = True
                logger.debug(f"Target '{target}' validated as a single IP address.")
            except ValueError:
                pass # Not a valid network or IP

        if not is_valid_target:
            error_message = f"Invalid target format: {target}. Please provide a valid IP address (e.g., 192.168.1.1) or CIDR network (e.g., 192.168.1.0/24)."
            logger.error(error_message)
            return {
                "status": "error",
                "message": error_message,
                "response_for_ui": error_message,
                "user_command": user_command,
                "module_name": "Network Discovery",
                "target": target,
                "ports": None,
                "structured_results": {},
                "raw_output": error_message,
                "error_output": error_message,
                "exit_code": 1
            }
        
        # Nmap command for host discovery (ping scan)
        # -sn: Ping scan (no port scan)
        # -PE: ICMP echo request (can be useful but might need root privileges)
        # -oX: XML output
        # -oN: Normal output
        # -oG: Grepable output
        nmap_command = [
            Config.NMAP_PATH,
            '-sn', # Ping scan - disables port scan
            '-PE', # ICMP echo request (requires root on Linux, may be blocked by firewalls)
            '-oX', self.output_file_path + '.xml',
            '-oN', self.output_file_path + '.nmap',
            '-oG', self.output_file_path + '.gnmap',
            target
        ]

        logger.info(f"Executing Nmap command for network discovery: {' '.join(nmap_command)}")

        try:
            process = subprocess.run(nmap_command, capture_output=True, text=True, check=False)

            if process.returncode != 0:
                # Nmap returns non-zero for hosts down, etc. Check if it's an actual error or just no hosts found
                if "0 hosts up" in process.stdout or "0 hosts up" in process.stderr:
                    response_message = f"Network discovery completed for {target}. No active hosts found."
                    return {
                        "status": "success", # Treat no hosts found as a success if Nmap ran fine
                        "message": response_message,
                        "response_for_ui": response_message,
                        "user_command": user_command,
                        "module_name": "Network Discovery",
                        "target": target,
                        "ports": None,
                        "structured_results": {"discovered_hosts": []},
                        "raw_output": process.stdout,
                        "error_output": process.stderr,
                        "exit_code": process.returncode
                    }
                else:
                    error_message = f"Nmap command failed with exit code {process.returncode}: {process.stderr}"
                    logger.error(error_message)
                    return {
                        "status": "error",
                        "message": error_message,
                        "response_for_ui": error_message,
                        "user_command": user_command,
                        "module_name": "Network Discovery",
                        "target": target,
                        "ports": None,
                        "structured_results": {},
                        "raw_output": process.stdout,
                        "error_output": process.stderr,
                        "exit_code": process.returncode
                    }

            # Parse Nmap XML output for discovered hosts
            discovered_hosts = self._parse_nmap_xml(self.output_file_path + '.xml')
            
            response_message = ""
            if discovered_hosts:
                response_message = f"Network discovery completed for {target}. Found {len(discovered_hosts)} active hosts:\n"
                for host in discovered_hosts:
                    response_message += f"- IP: {host.get('ip_address')}, Hostname: {host.get('hostname') if host.get('hostname') != 'N/A' else 'N/A'}, MAC: {host.get('mac_address')}\n"
            else:
                response_message = f"Network discovery completed for {target}. No active hosts found."
            
            result_dict = {
                "status": "success",
                "message": f"Network discovery completed for {target}. Found {len(discovered_hosts)} active hosts.",
                "response_for_ui": response_message,
                "user_command": user_command,
                "module_name": "Network Discovery",
                "target": target,
                "ports": None,
                "structured_results": {"discovered_hosts": discovered_hosts},
                "raw_output": process.stdout,
                "error_output": process.stderr,
                "exit_code": process.returncode
            }
            return result_dict

        except FileNotFoundError:
            error_message = f"Nmap command failed: Nmap executable not found at {Config.NMAP_PATH}"
            logger.error(error_message)
            return {
                "status": "error",
                "message": error_message,
                "response_for_ui": error_message,
                "user_command": user_command,
                "module_name": "Network Discovery",
                "target": target,
                "ports": None,
                "structured_results": {},
                "raw_output": error_message,
                "error_output": error_message,
                "exit_code": 1
            }
        except subprocess.CalledProcessError as e:
            error_message = f"Nmap command failed with error: {e.stderr or e.stdout}"
            logger.error(error_message)
            return {
                "status": "error",
                "message": error_message,
                "response_for_ui": error_message,
                "user_command": user_command,
                "module_name": "Network Discovery",
                "target": target,
                "ports": None,
                "structured_results": {},
                "raw_output": e.stdout,
                "error_output": e.stderr,
                "exit_code": e.returncode
            }
        except Exception as e:
            error_message = f"An unexpected error occurred during network discovery: {e}"
            logger.exception(error_message)
            return {
                "status": "error",
                "message": error_message,
                "response_for_ui": error_message,
                "user_command": user_command,
                "module_name": "Network Discovery",
                "target": target,
                "ports": None,
                "structured_results": {},
                "raw_output": error_message,
                "error_output": str(e),
                "exit_code": 1
            }

    def _parse_nmap_xml(self, xml_file):
        """
        Parses the Nmap XML output file for network discovery to extract active hosts.
        Returns a list of dictionaries, each representing a discovered host.
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = []
            for host_elem in root.findall('host'):
                status_elem = host_elem.find('status')
                if status_elem is not None and status_elem.get('state') == 'up':
                    ip_address = 'N/A'
                    mac_address = 'N/A'
                    hostname = 'N/A'

                    # Extract IP and MAC addresses
                    for address_elem in host_elem.findall('address'):
                        if address_elem.get('addrtype') == 'ipv4':
                            ip_address = address_elem.get('addr')
                        elif address_elem.get('addrtype') == 'mac':
                            mac_address = address_elem.get('addr')
                    
                    # Extract hostname (Nmap might resolve hostnames during discovery)
                    # Look for hostname where 'type' is 'user' or 'PTR' (reverse DNS)
                    hostnames_elem = host_elem.find('hostnames')
                    if hostnames_elem is not None:
                        for hn_elem in hostnames_elem.findall('hostname'):
                            if hn_elem.get('type') in ['user', 'PTR']: # Prefer user-defined or PTR
                                hostname = hn_elem.get('name')
                                if hostname: # Take the first valid one
                                    break
                        if not hostname and hostnames_elem.find('hostname') is not None: # Fallback to any hostname
                            hostname = hostnames_elem.find('hostname').get('name')


                    hosts.append({
                        "ip_address": ip_address,
                        "mac_address": mac_address,
                        "hostname": hostname
                    })
            return hosts
        except FileNotFoundError:
            logger.error(f"Nmap XML output file not found: {xml_file}")
            return []
        except ET.ParseError as e:
            logger.error(f"Error parsing Nmap XML file {xml_file}: {e}")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred during XML parsing: {e}")
            return []