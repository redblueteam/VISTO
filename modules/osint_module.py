# modules/osint_module.py

import requests
import socket
import ssl
import json
import logging
import ipaddress
import re
from datetime import datetime
from bs4 import BeautifulSoup
import shodan
import dns.resolver
import whois
import os

from config import Config
from modules.base_module import BaseModule

logger = logging.getLogger(__name__)

class OSINTModule(BaseModule):
    """
    A module for performing various OSINT (Open Source Intelligence) tasks.
    Requires a Shodan API Key to be configured in config.py or environment variables.
    """

    def __init__(self, session_id=None, project_name=None):
        super().__init__(session_id=session_id, project_name=project_name)
        
        self.output_file_base = os.path.join(self.base_output_dir, f"osint_{self.timestamp}") 
        self.log_file = self.get_module_log_file_path(f"osint.log") 
        
        logger.info(f"OSINTModule initialized. Output file base: {self.output_file_base}, Log file: {self.log_file}")

        self.shodan_api_key = os.getenv('SHODAN_API_KEY') or Config.SHODAN_API_KEY
        if not self.shodan_api_key:
            logger.warning("Shodan API Key not found. Shodan checks will be skipped.")
            self.api = None
        else:
            logger.info("Shodan API Key found. Attempting to initialize Shodan client.")
            try:
                self.api = shodan.Shodan(self.shodan_api_key)
                # Test API key by making a small call (e.g., info() for account limits)
                # If this fails, the APIError will be caught.
                account_info = self.api.info()
                logger.info(f"Shodan API client successfully initialized. Account credits: {account_info.get('usage_limits', {}).get('query_credits', 'N/A')}")
            except shodan.exception.APIError as e:
                logger.error(f"Failed to connect to Shodan API with provided key: {e}. Shodan checks will be skipped.", exc_info=True)
                self.api = None
            except Exception as e:
                logger.error(f"An unexpected error occurred during Shodan API initialization: {e}. Shodan checks will be skipped.", exc_info=True)
                self.api = None
        
        logger.debug(f"Shodan API client status after initialization: {'Initialized' if self.api else 'Not Initialized'}")

    def _get_whois_info(self, domain):
        """Fetches WHOIS information for a domain."""

        logger.info(f"Performing WHOIS check for {domain}...")
        whois_data = {}
        try:
            w = whois.whois(domain)
            raw_whois_text = w.text if w else None
            if w:               
                # Helper function to safely get attribute values, handling None and lists
                def get_attribute_value(obj, attr):
                    value = getattr(obj, attr, None)
                    if isinstance(value, (list, tuple)):
                        # Ensure all elements in a list are converted to string
                        return [str(item) for item in value if item is not None]
                    elif value is not None:
                        # Convert single values (like datetime objects) to string
                        return str(value)
                    return None

                whois_data = {
                    "domain_name": get_attribute_value(w, 'domain_name'),
                    "registrar": get_attribute_value(w, 'registrar'),
                    "creation_date": get_attribute_value(w, 'creation_date'),
                    "expiration_date": get_attribute_value(w, 'expiration_date'),
                    "updated_date": get_attribute_value(w, 'updated_date'),
                    "name_servers": get_attribute_value(w, 'name_servers'),
                    "emails": get_attribute_value(w, 'emails'), # This often includes admin/tech emails
                    "org": get_attribute_value(w, 'org'),
                    "city": get_attribute_value(w, 'city'),
                    "state": get_attribute_value(w, 'state'),
                    "country": get_attribute_value(w, 'country'),
                    "status": get_attribute_value(w, 'status'),
                    "dnssec": get_attribute_value(w, 'dnssec'), # DNSSEC status (True/False/None)
                    # Explicitly requested Admin Name and Admin Email (if available)
                    "admin_name": get_attribute_value(w, 'admin_name'),
                    "admin_email": get_attribute_value(w, 'admin_email'),
                    # "raw_text": get_attribute_value(w, 'text') # Full raw WHOIS text
                }
                
                # Remove keys with None values to keep structured results cleaner for LLM
                logger.info(f"WHOIS check for {domain} completed.")
            else:
                logger.warning(f"No WHOIS information found for {domain}.")
                whois_data = {"error": "No WHOIS information found for this target."}
            
        except Exception as e:
            logger.error(f"Error fetching WHOIS for {domain}: {e}", exc_info=True)
            whois_data = {"error": f"Failed to fetch WHOIS: {e}"}
        finally:
            logger.info(f"WHOIS check for {domain} completed.")
        
        # Add the raw_whois_text to the dictionary being returned.
        # This makes it available for the 'run' method to use in raw_output.
        whois_data['raw_whois_text'] = raw_whois_text 
        return whois_data

    def _get_subdomains(self, domain):
        """Performs subdomain enumeration using DNS brute-forcing with common subdomains."""
        subdomains = []
        common_subdomains = ['www', 'mail', 'ftp', 'blog', 'dev', 'test', 'api', 'admin', 'webmail', 'remote']
        
        for sub in common_subdomains:
            try:
                sub_domain = f"{sub}.{domain}"
                answers = dns.resolver.resolve(sub_domain, 'A')
                for rdata in answers:
                    subdomains.append({"subdomain": sub_domain, "ip_address": str(rdata)})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue # Subdomain does not exist
            except Exception as e:
                logger.warning(f"Error resolving subdomain {sub}.{domain}: {e}")
        return subdomains

    def _check_tls_info(self, fqdn):
        """Fetches TLS/SSL certificate information for an FQDN on port 443."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((fqdn, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract key info
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    # SANs (Subject Alternative Names)
                    san = []
                    for ext in cert.get('subjectAltName', []):
                        if isinstance(ext, tuple) and len(ext) == 2:
                            san.append({ext[0]: ext[1]})
                        else:
                            san.append(ext) # Fallback for unexpected formats

                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "subject_alt_names": san,
                        "signature_algorithm": cert.get('signatureAlgorithm'),
                        "public_key_info": {
                            "algorithm": cert.get('pubkeyinfo', {}).get('key_algorithm'),
                            "size": cert.get('pubkeyinfo', {}).get('rsa_public_key', {}).get('modulus_size'),
                        }
                    }
        except socket.timeout:
            logger.error(f"TLS check for {fqdn} timed out.")
            return {"error": "TLS check timed out."}
        except ConnectionRefusedError:
            logger.error(f"TLS check for {fqdn}: Connection refused (port 443 closed or no HTTPS).")
            return {"error": "Connection refused or no HTTPS on port 443."}
        except ssl.SSLError as e:
            logger.error(f"TLS/SSL error for {fqdn}: {e}")
            return {"error": f"SSL/TLS error: {e}"}
        except Exception as e:
            logger.error(f"Unexpected error during TLS check for {fqdn}: {e}")
            return {"error": f"An unexpected error occurred: {e}"}


    def run(self, params):
        """
        Executes various OSINT checks based on parameters.
        Expected params:
            - 'target_type': 'ip_address', 'fqdn', or 'domain'.
            - 'target': The IP address, FQDN, or domain name.
            - 'shodan_check': bool, whether to perform Shodan lookup.
            - 'whois_check': bool, whether to perform WHOIS lookup (for domains).
            - 'subdomain_enum': bool, whether to perform subdomain enumeration (for domains).
            - 'tls_check': bool, whether to perform TLS/SSL certificate check (for FQDNs).
        """
        # --- DEBUG LOGS ---
        logger.debug(f"OSINTModule.run received params: {json.dumps(params, indent=2)}") 
        # --- END DEBUG LOGS ---

        target = params.get('target')
        target_type = params.get('target_type')
        user_command = params.get('user_command', 'N/A')

        shodan_check = params.get('shodan_check')
        whois_check = params.get('whois_check')
        subdomain_enum = params.get('subdomain_enum')
        tls_check = params.get('tls_check')

        overall_results = {
            "target_info": {
                "original_target": target,
                "type": target_type
            },
            "checks_performed": {}
        }
        structured_results = overall_results
        raw_output_parts = []
        
        # --- 1. Resolve FQDN to IP if necessary ---
        resolved_ip = None
        if target_type == 'fqdn' or target_type == 'ip':
            try:
                # First, check if target is already an IP address
                ipaddress.ip_address(target)
                resolved_ip = target
                logger.debug(f"Target '{target}' identified as a direct IP address.")
                logger.debug(f"Resolved IP '{resolved_ip}' identified as a direct IP address.")
            except ValueError:
                # If not an IP, try to resolve as FQDN
                logger.debug(f"Target '{target}' is not a direct IP. Attempting FQDN resolution...")
                try:
                    resolved_ip = socket.gethostbyname(target)
                    overall_results["target_info"]["resolved_ip"] = resolved_ip
                    logger.info(f"FQDN '{target}' successfully resolved to IP: {resolved_ip}")
                except socket.gaierror:
                    error_message = f"Failed to resolve FQDN '{target}'. Hostname not found or temporary DNS issue."
                    logger.error(error_message)
                    return self.error_response(
                        error_message,
                        user_command=user_command,
                        module_name="osint_module",
                        target=target,
                        raw_output=error_message, # Include error in raw_output
                        structured_results=overall_results # Return partial results
                    )
                except Exception as e:
                    error_message = f"An unexpected error occurred during FQDN resolution for '{target}': {e}"
                    logger.error(error_message, exc_info=True)
                    return self.error_response(
                        error_message,
                        user_command=user_command,
                        module_name="osint_module",
                        target=target,
                        raw_output=error_message,
                        structured_results=overall_results
                    )
        
        # --- 2. Perform Shodan Check ---
        if shodan_check and self.api:
            logger.debug(f"Shodan check is enabled and API is ready. Target type: {target_type}, Original target: {target}, Resolved IP: {resolved_ip}")
            overall_results["checks_performed"]["shodan"] = {} # Initialize shodan check entry
            if resolved_ip: # Use the resolved IP for Shodan
                try:
                    logger.info(f"Performing Shodan API call for {resolved_ip}...")
                    shodan_data = self.api.host(resolved_ip)
                    logger.debug(f"Shodan API raw response for {resolved_ip}: {json.dumps(shodan_data)}") # This crucial debug log should now appear!
                    
                    # --- SHODAN DATA HANDLING FOR EMPTY/NO INFO ---
                    if shodan_data:
                        if "error" in shodan_data:
                            # Handle explicit API errors returned as part of the data (e.g., "No information available for that IP.")
                            if shodan_data.get("error") == "No information available for that IP.":
                                overall_results["checks_performed"]["shodan"]["status"] = "No information found on Shodan for this IP."
                                raw_output_parts.append(f"--- Shodan Host Data for {resolved_ip} ---\nStatus: No information found on Shodan for this IP.")
                                logger.info(f"Shodan check for {resolved_ip} completed: No information found.")
                            else:
                                # Other Shodan API errors returned in the data
                                shodan_error_msg = f"Shodan API returned error for {resolved_ip}: {shodan_data['error']}"
                                overall_results["checks_performed"]["shodan"]["error"] = shodan_error_msg
                                raw_output_parts.append(f"--- Shodan Host Data for {resolved_ip} ---\nError: {shodan_error_msg}")
                                logger.error(f"Shodan check for {resolved_ip} failed: {shodan_error_msg}")
                        elif shodan_data.get("matches") == []: # Specific case for an empty matches array from some Shodan searches
                            overall_results["checks_performed"]["shodan"]["status"] = "Shodan search returned no matches for this query."
                            raw_output_parts.append(f"--- Shodan Host Data for {resolved_ip} ---\nStatus: Shodan search returned no matches.")
                            logger.info(f"Shodan check for {resolved_ip} completed: No matches found.")
                        else:
                            # Valid data returned
                            overall_results["checks_performed"]["shodan"]["data"] = shodan_data
                            raw_output_parts.append(f"--- Shodan Host Data for {resolved_ip} ---\n{json.dumps(shodan_data, indent=2)}")
                            logger.info(f"Shodan check for {resolved_ip} completed successfully with data.")
                    else:
                        # Shodan API returned an empty or None response
                        shodan_error_msg = "Shodan API returned an empty or invalid response."
                        overall_results["checks_performed"]["shodan"]["error"] = shodan_error_msg
                        raw_output_parts.append(f"--- Shodan Host Data for {resolved_ip} ---\nError: {shodan_error_msg}")
                        logger.error(f"Shodan check for {resolved_ip} failed or returned empty/invalid data.")
                    # --- END SHODAN DATA HANDLING ---
                        
                except shodan.exception.APIError as e:
                    shodan_error = f"Shodan API error for {resolved_ip}: {e}"
                    overall_results["checks_performed"]["shodan"]["error"] = shodan_error
                    raw_output_parts.append(shodan_error)
                    logger.error(shodan_error)
                except Exception as e:
                    shodan_error = f"An unexpected error occurred during Shodan lookup for {resolved_ip}: {e}"
                    overall_results["checks_performed"]["shodan"]["error"] = shodan_error
                    raw_output_parts.append(shodan_error)
                    logger.error(shodan_error, exc_info=True)
            else: # This block is hit if resolved_ip is None here
                msg = "Shodan check skipped: Target did not resolve to a valid IP address."
                overall_results["checks_performed"]["shodan"]["status"] = msg
                raw_output_parts.append(msg)
                logger.warning(msg)
        elif shodan_check and not self.api:
            msg = "Shodan check skipped: Shodan API key is not configured or invalid."
            overall_results["checks_performed"]["shodan"] = {"status": msg}
            raw_output_parts.append(msg)
            logger.warning(msg)

        # --- 3. Perform WHOIS Check ---
        if whois_check and target_type == 'domain':
            whois_data = self._get_whois_info(target)
            
            # Extract the raw_whois_text and then assign whois_data to structured_results.
            # Pop removes the key from whois_data, keeping structured_results cleaner.
            raw_whois_text_for_output = whois_data.pop('raw_whois_text', None)
            
            # structured_results will now contain all keys from whois_data,
            # including those with None values, for a consistent schema.
            structured_results['checks_performed']['whois'] = whois_data # This uses the modified whois_data

            raw_output_parts.append(f"--- WHOIS Data for {target} ---")
            if "error" in whois_data:
                raw_output_parts.append(f"Error: {whois_data['error']}")
            else:
                # Define the order of fields for raw_output display.
                # This ensures consistent formatting.
                display_order = [
                    'domain_name', 'registrar', 'status', 'creation_date',
                    'expiration_date', 'updated_date', 'name_servers', 'emails',
                    'admin_name', 'admin_email', 'org', 'city', 'state', 'country',
                    'dnssec'
                ]
                
                # Format each field for raw output.
                # It will explicitly show "N/A" if a value is None.
                for key in display_order:
                    value = whois_data.get(key) # Get value from the data (which might be None)
                    display_key = key.replace('_', ' ').title() # Make it human-readable (e.g., 'creation_date' -> 'Creation Date')

                    if isinstance(value, list):
                        raw_output_parts.append(f"{display_key}: {', '.join(value) if value else 'N/A'}")
                    elif value is not None:
                        raw_output_parts.append(f"{display_key}: {value}")
                    else:
                        raw_output_parts.append(f"{display_key}: N/A") # Clearly indicate if data is missing

                # Add the full raw WHOIS record if available.
                if raw_whois_text_for_output:
                    raw_output_parts.append("\n--- Full Raw WHOIS Record ---")
                    raw_output_parts.append(raw_whois_text_for_output)
            raw_output_parts.append("\n") # Add a newline for separation

        # --- 4. Perform Subdomain Enumeration ---
        if subdomain_enum and target_type == 'domain':
            logger.info(f"Performing subdomain enumeration for {target}...")
            subdomains_found = self._get_subdomains(target)
            # Ensure subdomain_enumeration entry is always present
            if subdomains_found:
                overall_results["checks_performed"]["subdomain_enumeration"] = subdomains_found
                raw_output_parts.append(f"--- Subdomains Found for {target} ---\n{json.dumps(subdomains_found, indent=2)}")
                logger.info(f"Subdomain enumeration for {target} completed. Found {len(subdomains_found)} subdomains.")
            else:
                msg = "No common subdomains found."
                overall_results["checks_performed"]["subdomain_enumeration"] = {"status": msg}
                raw_output_parts.append(f"--- Subdomains Found for {target} ---\n{msg}")
                logger.info(f"Subdomain enumeration for {target} completed. {msg}")
        elif subdomain_enum and target_type != 'domain':
            msg = "Subdomain enumeration skipped: Only applicable to 'domain' target types."
            overall_results["checks_performed"]["subdomain_enumeration"] = {"status": msg}
            raw_output_parts.append(msg)
            logger.warning(msg)

        # --- 5. Perform TLS Check ---
        if tls_check and target_type == 'fqdn':
            logger.info(f"Performing TLS check for {target}...")
            tls_info = self._check_tls_info(target)
            # Ensure TLS check entry is always present
            if "error" in tls_info:
                overall_results["checks_performed"]["tls_info"] = {"error": tls_info["error"]}
                raw_output_parts.append(f"--- TLS/SSL Info for {target} ---\nError: {tls_info['error']}")
            else:
                overall_results["checks_performed"]["tls_info"] = tls_info
                raw_output_parts.append(f"--- TLS/SSL Info for {target} ---\n{json.dumps(tls_info, indent=2)}")
            logger.info(f"TLS check for {target} completed.")
        elif tls_check and target_type != 'fqdn':
            msg = "TLS check skipped: Only applicable to 'fqdn' target types."
            overall_results["checks_performed"]["tls_info"] = {"status": msg}
            raw_output_parts.append(msg)
            logger.warning(msg)
        
        final_raw_output = "\n\n".join(raw_output_parts)
        if not final_raw_output:
            final_raw_output = "No OSINT checks performed or no data retrieved."

        # Determine overall status
        status = "success"
        response_message = f"OSINT scan for {target_type} '{target}' completed."
        
        # --- Determine overall status more accurately ---
        all_requested_checks_successful = True
        any_check_requested = False

        # Add debug log for checks_performed before final status logic
        logger.debug(f"OSINT Final status logic: overall_results['checks_performed'] = {overall_results['checks_performed']}")

        # Iterate over the flags that were explicitly requested
        requested_checks = {
            "shodan": shodan_check,
            "whois": whois_check,
            "subdomain_enumeration": subdomain_enum,
            "tls_info": tls_check
        }

        for check_name, is_requested in requested_checks.items():
            if is_requested:
                any_check_requested = True
                check_data = overall_results["checks_performed"].get(check_name, {}) # Get data for this check, default to empty dict
                
                if "error" in check_data:
                    all_requested_checks_successful = False
                    status = "error" # If any check had a direct error, overall status is error
                    response_message += f"\nError in {check_name}: {check_data['error']}"
                elif "status" in check_data and "skipped" in check_data["status"]:
                    all_requested_checks_successful = False
                    if status == "success": # Only downgrade if not already error
                        status = "warning" # Use 'warning' if some checks were intentionally skipped (e.g., wrong target type)
                    response_message += f"\nNote: {check_name} was skipped: {check_data['status']}"
                elif "status" in check_data and ("No information found" in check_data["status"] or "No matches" in check_data["status"] or "No common subdomains" in check_data["status"]):
                    # This is a "soft failure" - check ran, but found no info. Keep overall status successful if no other errors.
                    if all_requested_checks_successful: # If still successful, keep as success, but add note
                        response_message += f"\nNote: {check_name} reported: {check_data['status']}"
                # If there's 'data' key, it implies success (even if data is empty).

        if not any_check_requested:
            status = "info" # No checks were enabled or requested
            response_message = f"No OSINT checks were enabled or requested for target '{target_type} {target}'."
        elif all_requested_checks_successful and any_check_requested:
            # If all requested checks either returned data, or explicitly returned a 'no info found' status
            status = "success" # All enabled checks ran successfully and returned data or status.
        # else: status is already error or warning from above

        return self.success_response( # Use success_response for 'success' or 'warning' status
            response_message,
            raw_output=final_raw_output,
            structured_results=overall_results,
            user_command=user_command,
            module_name="osint_module",
            target=target,
            status=status # Ensure the final determined status is passed to the response
        )

# Example usage (for testing this module directly, not part of the Flask app)
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    # Ensure you have a 'data/modules_output' directory for testing
    if not os.path.exists("data/modules_output"):
        os.makedirs("data/modules_output")

    # Adjust the test execution to correctly initialize the module
    test_session_id = "test_session_" + datetime.now().strftime("%H%M%S")
    test_project_name = "TEST_OSINT_CLI"
    
    # Initialize OSINTModule with session_id and project_name
    osint_tool = OSINTModule(session_id=test_session_id, project_name=test_project_name)

    print("\n--- Testing IP Address Shodan Check (8.8.8.8) ---")
    ip_results = osint_tool.run({
        'target_type': 'ip_address',
        'target': '8.8.8.8',
        'user_command': "osint ip 8.8.8.8 shodan_check true",
        'shodan_check': True
    })
    print(f"Results for 8.8.8.8:\n{json.dumps(ip_results, indent=2)}")

    print("\n--- Testing FQDN Shodan Check (google.com) ---")
    fqdn_target = "google.com"
    fqdn_results = osint_tool.run({
        'target_type': 'fqdn',
        'target': fqdn_target,
        'user_command': f"osint fqdn {fqdn_target} shodan_check true",
        'shodan_check': True
    })
    print(f"Results for {fqdn_target}:\n{json.dumps(fqdn_results, indent=2)}")

    print("\n--- Testing Domain Lookup (example.com) with Subdomain Enum and WHOIS ---")
    domain_target = "example.com"
    domain_results = osint_tool.run({
        'target_type': 'domain',
        'target': domain_target,
        'user_command': f"osint domain {domain_target} subdomain_enum true whois_check true",
        'subdomain_enum': True,
        'whois_check': True
    })
    print(f"Results for {domain_target}:\n{json.dumps(domain_results, indent=2)}")

    print("\n--- Testing FQDN TLS Check (neverssl.com) ---")
    non_https_fqdn = "neverssl.com" 
    tls_error_results = osint_tool.run({
        'target_type': 'fqdn',
        'target': non_https_fqdn,
        'user_command': f"osint fqdn {non_https_fqdn} tls_check true",
        'tls_check': True
    })
    print(f"Results for {non_https_fqdn}:\n{json.dumps(tls_error_results, indent=2)}")

    print("\n--- Testing FQDN that fails to resolve (nonexistent.domain.xyz) ---")
    non_existent_fqdn = "nonexistent.domain.xyz"
    no_resolve_results = osint_tool.run({
        'target_type': 'fqdn',
        'target': non_existent_fqdn,
        'user_command': f"osint fqdn {non_existent_fqdn} shodan_check true",
        'shodan_check': True
    })
    print(f"Results for {non_existent_fqdn}:\n{json.dumps(no_resolve_results, indent=2)}")

    print("\n--- Testing IP Shodan Check (IP not found on Shodan, e.g., private IP) ---")
    # Use a known IP that Shodan likely won't have info on (e.g., a private IP or a very new/obscure one)
    no_shodan_info_ip = "192.168.1.1" # Example private IP
    no_shodan_info_results = osint_tool.run({
        'target_type': 'ip_address',
        'target': no_shodan_info_ip,
        'user_command': f"osint ip {no_shodan_info_ip} shodan_check true",
        'shodan_check': True
    })
    print(f"Results for {no_shodan_info_ip}:\n{json.dumps(no_shodan_info_results, indent=2)}")

    print("\n--- Testing Shodan Search (No Matches - for a query) ---")
    # This scenario is less likely with host() but common with search().
    # Adding a placeholder to demonstrate the handling if it returns {"matches": []}
    # For host(), it's usually "No information available for that IP."
    # If the Shodan API was used with api.search() this would be relevant.
    # For now, it handles a potential future edge case or a misinterpretation of host() output.
    empty_matches_shodan_results = osint_tool.run({
        'target_type': 'ip_address', # Or fqdn
        'target': '1.1.1.1', # A real IP, but we'll simulate empty matches
        'user_command': 'osint ip 1.1.1.1 shodan_check true',
        'shodan_check': True
    })
    # Manually simulate the Shodan response for testing the branch
    # empty_matches_shodan_results['structured_results']['checks_performed']['shodan'] = {'matches': []} 
    # print(f"Results for simulated empty matches:\n{json.dumps(empty_matches_shodan_results, indent=2)}")