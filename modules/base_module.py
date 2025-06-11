# modules/base_module.py
import os
import json
import logging
import socket
import ipaddress
from datetime import datetime
from flask import session, current_app

# Ensure Config is properly imported from the config.py
from config import Config

logger = logging.getLogger(__name__)

class BaseModule:
    def __init__(self, session_id=None, project_name=None):
        self.session_id = session_id
        self.project_name = project_name
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Determine username for path. Fallback if not in session (e.g., direct module call for testing)
        username_for_path = session.get('username') if 'username' in session else 'default_user'
        
        # Base directory for all module-specific outputs (like Nmap XML)
        if self.project_name and self.session_id:
            project_base_dir = os.path.join(Config.DATA_DIR, "projects", username_for_path, self.project_name)
            self.base_output_dir = os.path.join(project_base_dir, self.session_id)
            os.makedirs(self.base_output_dir, exist_ok=True)
        else:
            self.base_output_dir = os.path.join(Config.DATA_DIR, "temp_module_output", username_for_path, self.timestamp)
            os.makedirs(self.base_output_dir, exist_ok=True)
            logger.warning(f"BaseModule initialized without full project/session context. Output will go to: {self.base_output_dir}")

        # Directory for module-specific log files (e.g., raw Nmap stdout)
        self.session_log_dir = os.path.join(Config.LOG_DIR, self.session_id if self.session_id else "temp_logs")
        os.makedirs(self.session_log_dir, exist_ok=True)


        logger.info(f"BaseModule initialized for session: {self.session_id}, project: {self.project_name}, output_dir: {self.base_output_dir}")

    def get_module_log_file_path(self, log_filename):
        """Returns the full path for a module-specific log file."""
        return os.path.join(self.session_log_dir, log_filename)

    def get_module_output_file_path(self, module_output_base_filename):
        """
        Generates a standardized output file path for a module within the session's output directory.
        This is for structured outputs like Nmap XML/JSON files.
        e.g., data/projects/<user>/<project_name>/<session_id>/<module_output_base_filename>
        """
        return os.path.join(self.base_output_dir, module_output_base_filename)

    def _is_allowed_target(self, target):
        """
        Validates if the target IP address or CIDR network is allowed based on
        Config.ALLOW_EXTERNAL_SCANNING and Config.INTERNAL_IP_RANGES.
        Returns True if allowed, False otherwise.
        """
        try:
            network_or_host = ipaddress.ip_network(target, strict=False)

            if Config.ALLOW_EXTERNAL_SCANNING:
                return True
            else:
                for internal_range_str in Config.INTERNAL_IP_RANGES:
                    internal_net = ipaddress.ip_network(internal_range_str, strict=False)
                    if network_or_host.overlaps(internal_net):
                        return True
                logger.warning(f"Target '{target}' is not within allowed internal IP ranges as per config.py.")
                return False
        except ValueError as e:
            logger.error(f"Invalid IP address or network format for target '{target}' during policy check: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during target policy validation for '{target}': {e}")
            return False

    def _validate_target_scope(self, target):
        """
        Wrapper for target scope validation, used before executing scans.
        Returns (True, None) if target is allowed, or (False, error_message) if not.
        """
        is_allowed = self._is_allowed_target(target)
        if not is_allowed:
            error_msg = (f"Target '{target}' is outside the allowed scanning scope. "
                         "Please configure ALLOW_EXTERNAL_SCANNING in config.py "
                         "or ensure the target is within INTERNAL_IP_RANGES.")
            logger.error(error_msg)
            return False, error_msg
        return True, None

    def _log_raw_output_to_file(self, module_name, raw_output):
        """
        Logs the raw output to a module-specific file within the session's log directory.
        This is separate from the DB save in app.py.
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "module_name": module_name,
            "raw_output": raw_output
        }
        
        log_file_path = self.get_module_log_file_path(f"{module_name}.log")
        try:
            with open(log_file_path, 'a') as f:
                f.write(json.dumps(log_entry, indent=2) + ",\n") # Append with comma for potential JSON array
            logger.debug(f"Raw output written to {log_file_path}")
        except Exception as e:
            logger.error(f"Failed to write raw output to log file {log_file_path}: {e}")

    def success_response(self, message, raw_output=None, structured_results=None, exit_code=0, 
                         target="N/A", ports="N/A", user_command="N/A", module_name="N/A", 
                         error_output=None, llm_analysis="N/A", status="success"):
        """Standard success response format. Includes new params for consistency."""
        self._log_raw_output_to_file(module_name, raw_output)
        
        return {
            "status": status,
            "message": message,
            "raw_output": raw_output if raw_output is not None else "",
            "structured_results": structured_results if structured_results is not None else {},
            "exit_code": exit_code,
            "target": target,
            "ports": ports,
            "user_command": user_command,
            "module_name": module_name,
            "error_output": error_output if error_output is not None else "",
            "llm_analysis": llm_analysis
        }

    def error_response(self, message, raw_output=None, structured_results=None, error_output=None, exit_code=1, 
                       target="N/A", ports="N/A", user_command="N/A", module_name="N/A", llm_analysis="N/A"):
        """Standard error response format. Includes new params for consistency."""
        logger.error(f"Module Error: {message}")
        if error_output:
            logger.error(f"Detailed Error Output: {error_output}")
        
        self._log_raw_output_to_file(module_name, raw_output or error_output)

        return {
            "status": "error",
            "message": message,
            "raw_output": raw_output if raw_output is not None else "",
            "structured_results": structured_results if structured_results is not None else {},
            "error_output": error_output if error_output is not None else "",
            "exit_code": exit_code,
            "target": target,
            "ports": ports,
            "user_command": user_command,
            "module_name": module_name,
            "llm_analysis": llm_analysis
        }

    def run(self, command_params):
        raise NotImplementedError("Subclasses must implement the 'run' method")