# modules/ip_scan.py

import logging
import ipaddress
import subprocess
import os
import json
from datetime import datetime
import shlex
import socket
import xml.etree.ElementTree as ET
import re

from config import Config
from modules.base_module import BaseModule # Ensure BaseModule is correctly imported

logger = logging.getLogger(__name__)

class IPScanModule(BaseModule):
    """
    A module for performing IP address scanning (e.g., port scanning with Nmap).
    Supports single IP, comma-separated IPs/FQDNs, and various Nmap flags.
    """

    def __init__(self, session_id=None, project_name=None):
        super().__init__(session_id=session_id, project_name=project_name)
        self.log_file = self.get_module_log_file_path(f"ip_scan.log")
        self.output_file_base = self.get_module_output_file_path(f"ip_scan_nmap_output")
        logger.info(f"IPScanModule initialized. Log file: {self.log_file}, Output file base: {self.output_file_base}")

    def _resolve_target(self, target):
        """
        Resolves an FQDN to an IP address. If target is already an IP, returns it.
        Returns a list of resolved IPs, or an empty list if resolution fails.
        """
        resolved_ips = []
        try:
            # Check if it's already an IP address
            ipaddress.ip_address(target)
            resolved_ips.append(target)
        except ValueError:
            # Not an IP, attempt DNS resolution (FQDN)
            try:
                # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
                _hostname, _aliases, ip_addresses = socket.gethostbyname_ex(target)
                resolved_ips.extend(ip_addresses)
                logger.debug(f"Resolved FQDN '{target}' to IPs: {ip_addresses}")
            except socket.gaierror as e:
                logger.error(f"Failed to resolve FQDN '{target}': {e}")
            except Exception as e:
                logger.error(f"Unexpected error resolving target '{target}': {e}")
        return resolved_ips

    def run(self, params):
        """
        Executes the IP scan command.
        Expected params:
            - 'target_ip': The IP address or FQDN (can be comma-separated list).
            - 'ports': Comma-separated list of ports (e.g., "80,443,22", or "all").
            - Optional flags: 'full_scan', 'udp_scan', 'version_detection', 'os_detection', 'script_scan'
        """
        user_command = params.get('user_command', 'N/A')
        original_targets_str = params.get('target_ip')
        ports = params.get('ports')
        module_name = params.get('module_name', 'ip_scan')

        if not original_targets_str:
            return self.error_response(
                "IP scan target IP(s)/FQDN(s) is missing.",
                user_command=user_command,
                module_name=module_name,
                target=original_targets_str,
                ports=ports
            )

        # Split multiple targets and resolve FQDNs
        targets_to_scan = []
        for target_part in original_targets_str.split(','):
            target_part = target_part.strip()
            if not target_part:
                continue
            resolved_ips = self._resolve_target(target_part)
            if resolved_ips:
                # Validate scope for each resolved IP
                for ip in resolved_ips:
                    is_allowed, error_msg = self._validate_target_scope(ip)
                    if not is_allowed:
                        return self.error_response(
                            f"Target '{ip}' (from '{target_part}') is outside the allowed scanning scope. {error_msg}",
                            user_command=user_command,
                            module_name=module_name,
                            target=original_targets_str,
                            ports=ports,
                            error_output=error_msg
                        )
                    targets_to_scan.append(ip)
            else:
                return self.error_response(
                    f"Failed to resolve or validate target: '{target_part}'. Ensure it is a valid IP or FQDN.",
                    user_command=user_command,
                    module_name=module_name,
                    target=original_targets_str,
                    ports=ports,
                    error_output=f"Could not resolve/validate {target_part}"
                )
        
        if not targets_to_scan:
            return self.error_response(
                f"No valid targets found after processing '{original_targets_str}'.",
                user_command=user_command,
                module_name=module_name,
                target=original_targets_str,
                ports=ports
            )

        # Build Nmap command
        nmap_command = [Config.NMAP_PATH]
        
        # --- Ports handling logic ---
        ports_for_logging = "N/A"
        if not ports: # If ports are not provided, default to top 500
            nmap_command.extend(['--top-ports', '500'])
            ports_for_logging = "top 500"
            logger.info("No ports specified. Defaulting to top 500 ports scan.")
        elif ports.lower() == 'all':
            nmap_command.extend(['-p-', '--max-rate', '500']) # Full port scan, limit rate
            ports_for_logging = "all"
            logger.info("Performing a full port scan.")
        elif re.match(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$', ports):
             nmap_command.extend(['-p', ports])
             ports_for_logging = ports
             logger.info(f"Scanning specified ports: {ports}.")
        else:
            return self.error_response(
                f"Invalid port specification: '{ports}'. Use comma-separated ports (e.g., '22,80,443'), 'all', or leave empty for top 500.",
                user_command=user_command,
                module_name=module_name,
                target=original_targets_str,
                ports=ports # Use the original 'ports' for error message
            )
        # --- END : Ports handling logic ---

        # Add flags
        if params.get('version_detection'):
            nmap_command.append('-sV')
        if params.get('os_detection'):
            nmap_command.append('-O')
        if params.get('full_scan'): # Often implies -sV -O and common scripts
            nmap_command.extend(['-sC', '-sV', '-O']) # -sC for default scripts, -sV for version, -O for OS
        if params.get('udp_scan'):
            nmap_command.append('-sU')
        if params.get('script_scan'):
            nmap_command.append('-sC') # Default script scan

        # Output options
        xml_output_file = f"{self.output_file_base}.xml"
        nmap_output_file = f"{self.output_file_base}.nmap"
        nmap_command.extend(['--open', '-oX', xml_output_file, '-oN', nmap_output_file])
        
        # Add targets to the command
        nmap_command.extend(targets_to_scan)

        command_str = shlex.join(nmap_command)
        logger.info(f"Running Nmap command: {command_str}")

        raw_output = ""
        error_output = ""
        exit_code = 1
        structured_results = {}

        try:
            process = subprocess.run(
                nmap_command,
                capture_output=True,
                text=True,
                check=False,
                encoding='utf-8'
            )
            raw_output = process.stdout
            error_output = process.stderr
            exit_code = process.returncode

            logger.debug(f"Nmap Raw Output:\n{raw_output}")
            if error_output:
                logger.error(f"Nmap Stderr:\n{error_output}")

            if exit_code != 0:
                overall_status_message = f"Nmap scan for '{original_targets_str}' completed with exit code {exit_code}. Error: {raw_output.strip() or error_output.strip()}"
                logger.error(overall_status_message)
                return self.error_response(
                    overall_status_message,
                    raw_output=raw_output,
                    error_output=error_output,
                    exit_code=exit_code,
                    user_command=user_command,
                    module_name=module_name,
                    target=original_targets_str,
                    ports=ports
                )
            
            # Parse XML output for structured results
            structured_results = self._parse_nmap_xml(xml_output_file)
            if "error" in structured_results:
                return self.error_response(
                    f"Nmap scan succeeded, but failed to parse XML: {structured_results['error']}",
                    raw_output=raw_output,
                    error_output=structured_results['error'],
                    exit_code=exit_code,
                    user_command=user_command,
                    module_name=module_name,
                    target=original_targets_str,
                    ports=ports
                )

            overall_status_message = f"Nmap scan for '{original_targets_str}' completed successfully."
            return self.success_response(
                overall_status_message,
                raw_output=raw_output,
                structured_results=structured_results,
                exit_code=exit_code,
                user_command=user_command,
                module_name=module_name,
                target=original_targets_str,
                ports=ports
            )

        except FileNotFoundError:
            error_msg = f"Nmap not found at {Config.NMAP_PATH}. Please ensure Nmap is installed and configured in config.py."
            logger.error(error_msg)
            return self.error_response(
                error_msg,
                user_command=user_command,
                module_name=module_name,
                target=original_targets_str,
                ports=ports
            )
        except Exception as e:
            error_msg = f"An unexpected error occurred during IP scan: {e}"
            logger.error(error_msg, exc_info=True)
            return self.error_response(
                error_msg,
                raw_output=raw_output,
                error_output=str(e),
                exit_code=1,
                user_command=user_command,
                module_name=module_name,
                target=original_targets_str,
                ports=ports
            )

    def _parse_nmap_xml(self, xml_file):
        """
        Parses the Nmap XML output file and extracts relevant information.
        Returns a dictionary of structured results.
        """
        results = {"hosts": []}
        if not os.path.exists(xml_file):
            logger.warning(f"Nmap XML output file not found: {xml_file}. Cannot parse structured results.")
            return {"error": "Nmap XML output file not found."}

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall('host'):
                host_info = {}
                
                # IP Address
                address_elem = host_elem.find('address')
                if address_elem is not None and address_elem.get('addrtype') == 'ipv4':
                    host_info['ip_address'] = address_elem.get('addr')

                # Hostname (if resolved)
                hostnames_elem = host_elem.find('hostnames')
                if hostnames_elem is not None:
                    for hn_elem in hostnames_elem.findall('hostname'):
                        if hn_elem.get('type') == 'user' or hn_elem.get('type') == 'PTR':
                            host_info['hostname'] = hn_elem.get('name')
                            break # Take the first meaningful hostname

                # State (host status: up/down)
                status_elem = host_elem.find('status')
                if status_elem is not None:
                    host_info['status'] = status_elem.get('state')
                    if host_info['status'] == 'down':
                        # If host is down, no further info is relevant
                        if host_info:
                            results["hosts"].append(host_info)
                        continue # Skip to next host

                # Open Ports
                ports_elem = host_elem.find('ports')
                open_ports = []
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        state_elem = port_elem.find('state')
                        if state_elem is not None and state_elem.get('state') == 'open':
                            port_info = {
                                'portid': port_elem.get('portid'),
                                'protocol': port_elem.get('protocol')
                            }
                            service_elem = port_elem.find('service')
                            if service_elem is not None:
                                port_info['name'] = service_elem.get('name')
                                port_info['product'] = service_elem.get('product')
                                port_info['version'] = service_elem.get('version')
                            open_ports.append(port_info)
                    if open_ports:
                        host_info['open_ports'] = open_ports
                
                # OS Detection
                os_elem = host_elem.find('os')
                if os_elem is not None:
                    osmatch_elem = os_elem.find('osmatch')
                    if osmatch_elem is not None:
                        host_info['os_match'] = osmatch_elem.get('name')

                if host_info: # Only add host if we gathered any info
                    results["hosts"].append(host_info)

        except ET.ParseError as e:
            logger.error(f"Error parsing Nmap XML file {xml_file}: {e}")
            return {"error": f"Failed to parse Nmap XML: {e}"}
        except FileNotFoundError:
            logger.error(f"Nmap XML output file not found: {xml_file}")
            return {"error": "Nmap XML output file not found after scan."}
        except Exception as e:
            logger.error(f"An unexpected error occurred during XML parsing: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred during XML parsing: {e}"}

        return results