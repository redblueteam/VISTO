import os
import sqlite3
import hashlib
import pyotp
import qrcode
import base64
import json
import logging
import uuid
import shutil
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import re
import io

# Import the individual modules
from modules.network_discovery import NetworkDiscoveryModule
from modules.ip_scan import IPScanModule
from modules.osint_module import OSINTModule
from config import Config

# --- Flask Application Setup ---
app = Flask(__name__)
app.secret_key = Config.FLASK_SECRET_KEY
app.config['DATABASE'] = Config.DATABASE_PATH
app.config['LOG_DIR'] = Config.LOG_DIR
app.config['LLM_API_URL'] = Config.LLM_API_URL
app.config['LLM_MODEL_NAME'] = Config.LLM_MODEL_NAME
app.config['LLM_API_KEY'] = Config.LLM_API_KEY

# Configure logging for the Flask app
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(os.path.join(app.config['LOG_DIR'], 'app.log')),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

# Ensure data and log directories exist
os.makedirs(Config.DATA_DIR, exist_ok=True)
os.makedirs(app.config['LOG_DIR'], exist_ok=True)


# --- Database Setup ---
def get_db():
    """Establishes a database connection or returns the current one."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row 
    return db

def init_db():
    """Initializes the SQLite database and creates necessary tables."""
    
    db = get_db()
    cursor = db.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            twofa_secret TEXT
        )
    ''')

    # Projects table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            name TEXT NOT NULL,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (id)
        )
    ''')

    # Command History table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_command TEXT NOT NULL,
            module_name TEXT,
            target TEXT,
            ports TEXT,
            structured_results TEXT, -- Stored as JSON string
            raw_output TEXT,
            llm_analysis TEXT,
            status TEXT NOT NULL, -- 'success', 'error', 'pending'
            message TEXT,       -- Added back the 'message' column
            FOREIGN KEY (session_id) REFERENCES sessions (id),
            FOREIGN KEY (project_id) REFERENCES projects (id)
        )
    ''')
    db.commit()
    logger.info("Database initialized successfully.")

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- Global Helper Functions ---

# Helper function for text formatting
def _format_text_for_html_display(text):
    """
    Helper function to convert newline characters to <br> tags for HTML display.
    This should be used for any text destined for direct HTML display that might contain newlines.
    """
    if not isinstance(text, str):
        return str(text)
    return text.replace('\n\n', '<br><br>').replace('\n', '<br>')

def get_project_by_id(project_id):
    """Fetches a project by its ID."""
    db = get_db()
    return db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()

def create_session_db(project_id, session_name):
    """Creates a new session for a project in the database."""
    db = get_db()
    session_id = str(uuid.uuid4())
    try:
        db.execute("INSERT INTO sessions (id, project_id, name) VALUES (?, ?, ?)",
                   (session_id, project_id, session_name))
        db.commit()
        return session_id
    except sqlite3.Error as e:
        logger.error(f"Database error creating session: {e}")
        return None

def end_session_in_db(session_id):
    """Marks a session as ended in the database."""
    db = get_db()
    try:
        db.execute("UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE id = ?", (session_id,))
        db.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error ending session: {e}")

def save_command_result(project_id, session_id, user_command, module_name, target, status, message, structured_results, raw_output, llm_analysis):
    """Saves a command's result to the history."""
    conn = get_db()
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    try:
        cursor.execute(
            "INSERT INTO command_history (project_id, session_id, user_command, module_name, target, status, message, structured_results, raw_output, llm_analysis, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (project_id, session_id, user_command, module_name, target, status, message, json.dumps(structured_results), raw_output, llm_analysis, timestamp)
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error saving command result: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Unexpected error saving command result: {e}", exc_info=True)

def get_project_command_history(project_id):
    """Fetches command history for a given project."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM command_history WHERE project_id = ? ORDER BY timestamp DESC", (project_id,))
    history = cursor.fetchall()
    return history


# --- AIAgent Class ---
class AIAgent:
    """
    Handles AI agent operations, including calling modules and LLM analysis.
    Modules are now passed dynamically.
    """
    def __init__(self, modules_dict):
        self.modules_dict = modules_dict

    def get_module_instance(self, module_name, session_id, project_name):
        """Factory method to get an instance of a specific module."""
        module_class = self.modules_dict.get(module_name)
        if module_class:
            return module_class(session_id=session_id, project_name=project_name)
        return None

    def _call_llm_api(self, prompt, is_general_query=False):
        """
        Sends a prompt to the LLM API for analysis and returns the HTML-formatted response.
        is_general_query flag allows skipping report formatting for simple chat.
        """
        llm_api_url = current_app.config['LLM_API_URL']
        llm_api_key = current_app.config['LLM_API_KEY']
        llm_model_name = current_app.config['LLM_MODEL_NAME']

        format_func = _format_text_for_html_display

        if not llm_api_url or not llm_api_key or not llm_model_name:
            logger.warning("LLM API URL, API Key, or Model Name not configured. Skipping LLM analysis.")
            return format_func("LLM analysis skipped: Configuration missing.")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {llm_api_key}" if llm_api_key else None
        }
        headers = {k: v for k, v in headers.items() if v is not None}

        data_for_llm = {
            "model": llm_model_name,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.2
        }

        try:
            response = requests.post(llm_api_url, headers=headers, json=data_for_llm, timeout=300) # Increased timeout
            response.raise_for_status()

            llm_response_data = response.json()
            
            logger.debug(f"Raw LLM API Response Data: {json.dumps(llm_response_data, indent=2)}")

            if 'choices' in llm_response_data and llm_response_data['choices']:
                first_choice = llm_response_data['choices'][0]
                if 'message' in first_choice and 'content' in first_choice['message']:
                    raw_llm_content = first_choice['message']['content']
                    cleaned_content = raw_llm_content.strip('\"')
                    
                    if is_general_query:
                        return format_func(cleaned_content)
                    else:
                        return format_func(cleaned_content)

            logger.warning(f"Unexpected LLM response structure: {llm_response_data}")
            return format_func("LLM analysis failed: Unexpected response format from LLM API.")

        except requests.exceptions.Timeout:
            logger.error(f"LLM analysis failed: Request timed out after {300} seconds.")
            return format_func("LLM analysis failed: Request timed out.")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"LLM analysis failed: Connection error: {e}")
            return format_func(f"LLM analysis failed: Connection error: {e}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"LLM analysis failed: HTTP error {e.response.status_code}: {e.response.text}")
            return format_func(f"LLM analysis failed: HTTP error {e.response.status_code}: {e.response.text}")
        except Exception as e:
            logger.error(f"LLM analysis failed: An unexpected error occurred: {e}", exc_info=True)
            return format_func(f"LLM analysis failed: An unexpected error occurred: {e}")


# --- Authentication and Session Management ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """
    Handles the root URL. Redirects to dashboard if logged in, otherwise to login.
    """
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash("Username and password cannot be empty.", "danger")
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists. Please choose a different one.", "warning")
        else:
            password_hash = generate_password_hash(password)
            try:
                db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, password_hash))
                db.commit()
                flash("Registration successful! Please log in.", "success")
                logger.info(f"User {username} registered successfully.")
                return redirect(url_for('login'))
            except sqlite3.Error as e:
                flash(f"Database error during registration: {e}", "danger")
                logger.error(f"Database error during registration for user {username}: {e}")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        twofa_code = request.form.get('2fa_code') # Optional 2FA code

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, password_hash, twofa_secret FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            # Check 2FA if enabled
            if user['twofa_secret']:
                if not twofa_code:
                    flash("2FA is enabled for this account. Please enter your 2FA code.", "info")
                    # Render login template again, possibly with a flag to show 2FA input
                    return render_template('login.html', show_2fa_input=True, username=username)
                
                totp = pyotp.TOTP(user['twofa_fa_secret'])
                if not totp.verify(twofa_code):
                    flash("Invalid 2FA code.", "danger")
                    return render_template('login.html', show_2fa_input=True, username=username)

            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("Logged in successfully!", "success")
            logger.info(f"User {username} logged in.")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # End current session if active
    if 'current_session_id' in session:
        end_session_in_db(session['current_session_id'])
        logger.info(f"Session {session['current_session_id']} ended due to logout.")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    username = session.get('username')
    
    db = get_db()
    cursor = db.cursor()

    # Fetch user's projects
    cursor.execute("SELECT id, name FROM projects WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    projects = cursor.fetchall()

    # Check 2FA status
    cursor.execute("SELECT twofa_secret FROM users WHERE id = ?", (user_id,))
    user_settings = cursor.fetchone()
    is_2fa_enabled = bool(user_settings and user_settings['twofa_secret'])
    qr_code_base64 = None
    temp_2fa_secret = None

    if not is_2fa_enabled and request.args.get('setup_2fa') == 'true':
        temp_2fa_secret = pyotp.random_base32()
        session['temp_2fa_secret'] = temp_2fa_secret
        
        otp_uri = pyotp.totp.TOTP(temp_2fa_secret).provisioning_uri(
            name=username,
            issuer_name="VISTO"
        )
        img = qrcode.make(otp_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')


    current_project_id = session.get('current_project_id')
    current_project_name = session.get('current_project_name')
    current_session_id = session.get('current_session_id')

    # --- Fetch the most recent command output for the current project ---
    most_recent_command_output = None
    if current_project_id:
        cursor.execute(
            "SELECT user_command, message, llm_analysis, status, raw_output FROM command_history WHERE project_id = ? ORDER BY timestamp DESC LIMIT 1",
            (current_project_id,)
        )
        recent_entry = cursor.fetchone()
        if recent_entry:
            display_message_content = recent_entry['message'] or ''
            final_display_html = display_message_content

            if recent_entry['llm_analysis'] and recent_entry['llm_analysis'] != 'N/A':
                if 'LLM analysis skipped' in recent_entry['llm_analysis'] or \
                   'Request timed out' in recent_entry['llm_analysis'] or \
                   'LLM analysis failed' in recent_entry['llm_analysis']:
                    final_display_html += f"<br><br>--- LLM Analysis ---<br>{recent_entry['llm_analysis']}"
                else:
                    final_display_html += f"<br><br><h3 class='text-lg font-semibold text-gray-800 mb-2'>LLM Analysis:</h3>{recent_entry['llm_analysis']}"
            
            most_recent_command_output = {
                'display_html': final_display_html,
                'status': recent_entry['status']
            }


    return render_template('dashboard.html',
                           username=username,
                           projects=projects,
                           is_2fa_enabled=is_2fa_enabled,
                           qr_code_base64=qr_code_base64,
                           temp_2fa_secret=temp_2fa_secret,
                           current_project_id=current_project_id,
                           current_project_name=current_project_name,
                           current_session_id=current_session_id,
                           most_recent_command_output=most_recent_command_output)

@app.route('/toggle_2fa', methods=['POST'])
@login_required
def toggle_2fa():
    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT twofa_secret FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if user and user['twofa_secret']:
        # 2FA is currently enabled, disable it
        db.execute("UPDATE users SET twofa_secret = NULL WHERE id = ?", (user_id,))
        db.commit()
        flash("Two-factor authentication disabled.", "info")
        logger.info(f"User {session['username']} disabled 2FA.")
    else:
        # 2FA is currently disabled, redirect to dashboard to start setup
        flash("Please scan the QR code to set up 2FA.", "info")
        return redirect(url_for('dashboard', setup_2fa='true'))
    
    return redirect(url_for('dashboard'))

@app.route('/verify_2fa_setup', methods=['POST'])
@login_required
def verify_2fa_setup():
    user_id = session['user_id']
    user_input_code = request.form.get('2fa_code')
    temp_secret = session.get('temp_2fa_secret')

    if not temp_secret:
        flash("2FA setup not initiated or session expired. Please try again.", "danger")
        return redirect(url_for('dashboard'))

    if not user_input_code:
        flash("Please enter the 2FA code.", "danger")
        return redirect(url_for('dashboard', setup_2fa='true'))

    totp = pyotp.TOTP(temp_secret)
    if totp.verify(user_input_code):
        db = get_db()
        db.execute("UPDATE users SET twofa_secret = ? WHERE id = ?", (temp_secret, user_id))
        db.commit()
        session.pop('temp_2fa_secret', None)
        flash("Two-factor authentication successfully enabled!", "success")
        logger.info(f"User {session['username']} enabled 2FA.")
    else:
        flash("Invalid 2FA code. Please try again.", "danger")
        return redirect(url_for('dashboard', setup_2fa='true'))

    return redirect(url_for('dashboard'))


@app.route('/create_project', methods=['POST'])
@login_required
def create_project_route():
    project_name = request.form['project_name']
    user_id = session['user_id']
    if not project_name:
        flash("Project name cannot be empty.", "danger")
    else:
        project_id = create_project_db(user_id, project_name)
        if project_id:
            flash(f"Project '{project_name}' created successfully!", "success")
            logger.info(f"User {session['username']} created project {project_name} ({project_id}).")
            session['current_project_id'] = project_id
            session['current_project_name'] = project_name
            
            session_name = f"Initial Session for {project_name} - {datetime.now().strftime('%Y%m%d%H%M%S')}"
            current_session_id = create_session_db(project_id, session_name)
            if current_session_id:
                session['current_session_id'] = current_session_id
                flash(f"New session '{session_name}' started.", "info")
                logger.info(f"New session {current_session_id} started for project {project_id}.")
            else:
                flash("Failed to create an initial session for the project.", "warning")
                logger.error(f"Failed to create initial session for project {project_id}.")
        else:
            flash("Failed to create project. Please try again.", "danger")
            logger.error(f"Failed to create project {project_name} for user {user_id}.")
    return redirect(url_for('dashboard'))

def create_project_db(user_id, project_name):
    """Helper to create project in DB."""
    db = get_db()
    project_id = str(uuid.uuid4()) # Generate a unique ID for the project
    try:
        db.execute("INSERT INTO projects (id, user_id, name) VALUES (?, ?, ?)",
                   (project_id, user_id, project_name))
        db.commit()
        return project_id
    except Exception as e:
        logger.error(f"Error creating project: {e}")
        return None

@app.route('/select_project/<project_id>', methods=['POST'])
@login_required
def select_project_route(project_id):
    user_id = session['user_id']
    db = get_db()
    
    project = get_project_by_id(project_id)
    if project and project['user_id'] == user_id:
        if session.get('current_session_id'):
            end_session_in_db(session['current_session_id'])
            logger.info(f"Session {session['current_session_id']} ended due to project change.")

        session['current_project_id'] = project_id
        session['current_project_name'] = project['name']
        
        session_name = f"Session for {project['name']} - {datetime.now().strftime('%Y%m%d%H%M%S')}"
        current_session_id = create_session_db(project_id, session_name)
        
        if current_session_id:
            session['current_session_id'] = current_session_id
            flash(f"Project '{project['name']}' selected and new session started.", "success")
            logger.info(f"Project {project_id} selected. New session {current_session_id} created.")
        else:
            flash("Failed to create a new session for the selected project.", "warning")
            logger.error(f"Failed to create session for selected project {project_id}.")

    else:
        flash("Project not found or you don't have access.", "danger")
        logger.warning(f"User {session['username']} attempted to select unauthorized project {project_id}.")
    return redirect(url_for('dashboard'))

@app.route('/delete_project/<project_id>', methods=['POST'])
@login_required
def delete_project_route(project_id):
    db = get_db()
    project = get_project_by_id(project_id)
    if project and project['user_id'] == session['user_id']:
        project_name = project['name']
        # If the deleted project is the current one, deselect it
        if session.get('current_project_id') == project_id:
            if 'current_session_id' in session:
                end_session_in_db(session['current_session_id'])
                logger.info(f"Session {session['current_session_id']} ended due to deletion of current project.")
            session.pop('current_project_id', None)
            session.pop('current_project_name', None)
            session.pop('current_session_id', None)

        try:
            # Delete associated sessions and command history first
            db.execute("DELETE FROM command_history WHERE project_id = ?", (project_id,))
            db.execute("DELETE FROM sessions WHERE project_id = ?", (project_id,))
            db.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            db.commit()

            # Remove project's data directory
            project_data_path = os.path.join(Config.DATA_DIR, session['username'], project_name)
            if os.path.exists(project_data_path):
                shutil.rmtree(project_data_path)
                logger.info(f"Removed project data directory: {project_data_path}")

            flash(f"Project '{project_name}' and all associated data deleted.", "success")
            logger.info(f"User {session['username']} deleted project {project_name} ({project_id}).")
        except Exception as e:
            flash(f"Error deleting project: {e}", "danger")
            logger.error(f"Error deleting project {project_id} for user {session['username']}: {e}")
    else:
        flash("Project not found or you don't have access.", "danger")
        logger.warning(f"User {session['username']} attempted to delete unauthorized project {project_id}.")
    return redirect(url_for('dashboard'))


@app.route('/project_history/<project_id>')
@login_required
def project_history(project_id):
    user_id = session.get('user_id')
    project = get_project_by_id(project_id)

    if not project or project['user_id'] != user_id:
        flash("Project not found or you don't have access.", "danger")
        return redirect(url_for('dashboard'))

    history = get_project_command_history(project_id)
    formatted_history = []
    for entry in history:
        mutable_entry = dict(entry)
        formatted_history.append(mutable_entry)

    return render_template('project_history.html', project_name=project['name'], history=formatted_history)


@app.route('/agent_command', methods=['POST'])
@login_required
def process_command():
    user_id = session.get('user_id')
    current_session_id = session.get('current_session_id')
    project_id = session.get('current_project_id')
    project_name = session.get('current_project_name')

    if not all([user_id, current_session_id, project_id, project_name]):
        return jsonify({'status': 'error', 'message': _format_text_for_html_display('Session or project not fully established.'), 'response_for_ui': _format_text_for_html_display('Session or project not fully established.')}), 400

    data = request.get_json()
    command_string = data.get('command')
    if not command_string:
        return jsonify({'status': 'error', 'message': _format_text_for_html_display('No command provided.'), 'response_for_ui': _format_text_for_html_display('No command provided.')}), 400

    try:
        command_parts = command_string.split(' ')
        module_name = command_parts[0].lower()
        command_args = command_parts[1:]

        params = {
            'user_command': command_string,
            'module_name': module_name,
            'session_id': current_session_id,
            'project_name': project_name
        }

        # --- General ask_ai and help commands ---
        if module_name == 'ask_ai':
            user_query = " ".join(command_args)
            if not user_query:
                response_text = _format_text_for_html_display("Please provide a query for the AI. Usage: ask_ai <your query>.")
            else:
                response_text = current_app.agent_instance._call_llm_api(
                    f"User asked: {user_query}. Provide a concise and helpful answer.",
                    is_general_query=True
                )
            return jsonify({
                "status": "success",
                "message": response_text,
                "response_for_ui": response_text,
                "user_command": command_string,
                "module_name": module_name,
                "target": "N/A", "ports": "N/A", "structured_results": {}, "raw_output": response_text,
                "error_output": "", "exit_code": 0, "llm_analysis": "N/A"
            })
        elif module_name == 'help':
            if not command_args:
                help_text = """
                Welcome to the VISTO AI Pentest Agent!
                
                Here are the main commands you can use:
                - `network_discovery &lt;target_ip_range_or_subnet&gt;`: Scans a network range for active hosts.
                - `ip_scan &lt;target_ip&gt; [port(s)] [flags...]`: Performs a port scan on a target IP or FQDN.
                - `osint &lt;target_type&gt; &lt;target&gt; [flags...]`: Gathers Open Source Intelligence.
                - `ask_ai &lt;query&gt;`: Ask the AI a general cybersecurity question.
                - `help [command]`: Get detailed help on a specific command.
                
                For detailed usage and examples of a specific command, type `help &lt;command_name&gt;`.
                Example: `help ip_scan`
                """
            else:
                cmd_to_help = command_args[0].lower()
                if cmd_to_help == 'network_discovery':
                    help_text = """
                    **`network_discovery` Command**
                    
                    **Purpose:** Discovers active hosts within a specified IP range or subnet. It identifies live systems that can then be targeted for further scans.
                    
                    **Usage:**
                    `network_discovery &lt;target_ip_range_or_subnet&gt;`
                    
                    **Arguments:**
                    - `&lt;target_ip_range_or_subnet&gt;`: The network range in CIDR notation (e.g., `192.168.1.0/24`) or a single IP address (e.g., `192.168.1.1`).
                    
                    **Examples:**
                    - `network_discovery 192.168.1.0/24` (Scans the entire 192.168.1.x network)
                    - `network_discovery 10.0.0.1` (Checks if a single host is up)
                    """
                elif cmd_to_help == 'ip_scan':
                    help_text = """
                    **`ip_scan` Command**
                    
                    **Purpose:** Performs a port scan on a target IP address or Fully Qualified Domain Name (FQDN) to identify open ports, running services, and potentially operating system information.
                    
                    **Usage:**
                    `ip_scan &lt;target_ip_or_fqdn&gt; [port(s)] [flags...]`
                    
                    **Arguments:**
                    - `&lt;target_ip_or_fqdn&gt;`: The IP address (e.g., `192.168.1.51`) or FQDN (e.g., `example.com`, `www.example.com`). Multiple targets can be separated by commas (e.g., `192.168.1.51,example.com`).
                    - `[port(s)]` (Optional): Specifies which ports to scan.
                        - `&lt;port_number&gt;`: A single port (e.g., `80`).
                        - `&lt;port_list&gt;`: Comma-separated list of ports (e.g., `22,80,443`).
                        - `&lt;port_range&gt;`: A range of ports (e.g., `1-1024`).
                        - `all`: Scans all 65535 ports (can be very slow).
                        - **If omitted:** Defaults to scanning Nmap's top 500 most common ports.
                    
                    **Flags (Optional):**
                    - `full_scan`: Enables a more comprehensive scan (implies `-sC`, `-sV`, `-O`).
                    - `udp_scan`: Scans UDP ports (requires root privileges).
                    - `version_detection`: Attempts to determine service versions running on open ports (`-sV`).
                    - `os_detection`: Attempts to guess the operating system of the target (`-O`).
                    - `script_scan`: Runs Nmap's default safe scripts (`-sC`) against open ports.
                    
                    **Examples:**
                    - `ip_scan 192.168.1.1` (Scans top 500 ports on 192.168.1.1)
                    - `ip_scan 192.168.1.1 80,443,22` (Scans specific TCP ports)
                    - `ip_scan example.com 1-1000 version_detection` (Scans port range with version detection)
                    - `ip_scan 10.0.0.5 all os_detection` (Full TCP scan with OS detection)
                    - `ip_scan 192.168.1.10,server.local full_scan` (Scan multiple targets comprehensively)
                    """
                elif cmd_to_help == 'osint':
                    help_text = """
                    **`osint` Command**
                    
                    **Purpose:** Gathers Open Source Intelligence (OSINT) about a target (IP address, domain, or FQDN). This helps in passive reconnaissance.
                    
                    **Usage:**
                    `osint &lt;target_type&gt; &lt;target_value&gt; [flags...]`
                    
                    **Arguments:**
                    - `&lt;target_type&gt;`: Specifies the type of target. Choose one:
                        - `ip`: For IP addresses (e.g., `8.8.8.8`)
                        - `domain`: For root domains (e.g., `example.com`)
                        - `fqdn`: For Fully Qualified Domain Names (e.g., `www.example.com`, `mail.example.com`)
                    - `&lt;target_value&gt;`: The actual IP address, domain, or FQDN to perform OSINT on.
                    
                    **Flags (Optional):**
                    - `shodan_check`: Queries Shodan for information about the target IP. (Requires Shodan API Key in config.py)
                    - `subdomain_enum`: Attempts to find subdomains for a given domain/FQDN.
                    - `tls_check`: Retrieves SSL/TLS certificate information for a domain/FQDN.
                    - `whois_check`: Performs a WHOIS lookup for domain registration details.
                    
                    **Examples:**
                    - `osint ip 8.8.8.8 shodan_check`
                    - `osint domain example.com whois_check subdomain_enum`
                    - `osint fqdn mail.google.com tls_check`
                    """
                elif cmd_to_help == 'ask_ai':
                    help_text = """
                    **`ask_ai` Command**
                    
                    **Purpose:** Allows you to ask the AI agent general cybersecurity questions or for advice. It leverages the underlying Large Language Model (LLM) for direct conversation.
                    
                    **Usage:**
                    `ask_ai &lt;your query&gt;`
                    
                    **Arguments:**
                    - `&lt;your query&gt;`: Any question or topic related to cybersecurity you want to discuss with the AI.
                    
                    **Examples:**
                    - `ask_ai What is a SQL injection attack?`
                    - `ask_ai How can I protect my home network?`
                    - `ask_ai Explain the difference between encryption and hashing.`
                    """
                elif cmd_to_help == 'help':
                    help_text = "You're already using the `help` command! Just `help` for a list of main commands, or `help &lt;command_name&gt;` for specific details about a command."
                else:
                    help_text = f"Help not available for command: `{cmd_to_help}`.<br>Type `help` for a list of all commands."
            
            final_response = {
                "status": "success",
                "message": _format_text_for_html_display(help_text),
                "response_for_ui": _format_text_for_html_display(help_text),
                "user_command": command_string,
                "module_name": module_name,
                "target": "N/A", "ports": "N/A", "structured_results": {}, "raw_output": _format_text_for_html_display(help_text),
                "error_output": "", "exit_code": 0, "llm_analysis": "N/A"
            }
            return jsonify(final_response)

        # --- Specific handling for 'network_discovery', 'ip_scan', 'osint' modules ---
        elif module_name in ['network_discovery', 'ip_scan', 'osint']:
            if module_name == 'network_discovery':
                if len(command_args) < 1:
                    error_message = "Usage: network_discovery <target_ip_range_or_subnet>"
                    logger.error(error_message)
                    return jsonify({
                        "status": "error",
                        "message": _format_text_for_html_display(error_message),
                        "response_for_ui": _format_text_for_html_display(error_message),
                        "user_command": command_string,
                        "module_name": module_name,
                        "target": "N/A",
                        "ports": "N/A",
                        "structured_results": {},
                        "raw_output": _format_text_for_html_display(error_message),
                        "error_output": error_message,
                        "exit_code": 1,
                        "llm_analysis": _format_text_for_html_display(f"LLM analysis not applicable due to module error: {error_message}")
                    })
                params['target_ip_range_or_subnet'] = command_args[0]
                params['target'] = command_args[0]

            elif module_name == 'ip_scan':
                if len(command_args) < 1:
                    error_message = "Usage: ip_scan <target_ip> [port(s)] [flags...]"
                    logger.error(error_message)
                    return jsonify({
                        "status": "error",
                        "message": _format_text_for_html_display(error_message),
                        "response_for_ui": _format_text_for_html_display(error_message),
                        "user_command": command_string,
                        "module_name": module_name,
                        "target": "N/A",
                        "ports": "N/A",
                        "structured_results": {},
                        "raw_output": _format_text_for_html_display(error_message),
                        "error_output": error_message,
                        "exit_code": 1,
                        "llm_analysis": _format_text_for_html_display(f"LLM analysis not applicable due to module error: {error_message}")
                    })
                
                params['target_ip'] = command_args[0]
                params['target'] = command_args[0]

                if len(command_args) > 1:
                    params['ports'] = command_args[1]
                    flag_start_index = 2 
                else:
                    params['ports'] = None
                    flag_start_index = 1 

                # Parse optional flags for ip_scan
                for i in range(flag_start_index, len(command_args)):
                    arg = command_args[i]
                    if arg == 'full_scan': params['full_scan'] = True
                    elif arg == 'udp_scan': params['udp_scan'] = True
                    elif arg == 'version_detection': params['version_detection'] = True
                    elif arg == 'os_detection': params['os_detection'] = True
                    elif arg == 'script_scan': params['script_scan'] = True

            elif module_name == 'osint':
                if len(command_args) < 2:
                    error_message = "Usage: osint <target_type> <target> [flags...]"
                    logger.error(error_message)
                    return jsonify({
                        "status": "error",
                        "message": _format_text_for_html_display(error_message),
                        "response_for_ui": _format_text_for_html_display(error_message),
                        "user_command": command_string,
                        "module_name": module_name,
                        "target": "N/A",
                        "ports": "N/A",
                        "structured_results": {},
                        "raw_output": _format_text_for_html_display(error_message),
                        "error_output": error_message,
                        "exit_code": 1,
                        "llm_analysis": _format_text_for_html_display(f"LLM analysis not applicable due to module error: {error_message}")
                    })
                
                params['target_type'] = command_args[0].lower()
                params['target'] = command_args[1]

                valid_osint_target_types = ['ip', 'fqdn', 'domain']
                if params['target_type'] not in valid_osint_target_types:
                    error_message = f"Invalid target type for OSINT: '{params['target_type']}'. Supported types are: {', '.join(valid_osint_target_types)}."
                    logger.error(error_message)
                    return jsonify({
                        "status": "error",
                        "message": _format_text_for_html_display(error_message),
                        "response_for_ui": _format_text_for_html_display(error_message),
                        "user_command": command_string,
                        "module_name": module_name,
                        "target": params['target'],
                        "ports": "N/A",
                        "structured_results": {},
                        "raw_output": _format_text_for_html_display(error_message),
                        "error_output": error_message,
                        "exit_code": 1,
                        "llm_analysis": _format_text_for_html_display(f"LLM analysis not applicable due to module error: {error_message}")
                    })

                for i in range(2, len(command_args)):
                    arg = command_args[i]
                    if arg == 'ip_geolocation': params['ip_geolocation'] = True
                    elif arg == 'reverse_dns': params['reverse_dns'] = True
                    elif arg == 'shodan_check': params['shodan_check'] = True
                    elif arg == 'shodan_check_for_fqdn_ips': params['shodan_check_for_fqdn_ips'] = True
                    elif arg == 'subdomain_enum': params['subdomain_enum'] = True
                    elif arg == 'tls_check': params['tls_check'] = True
                    elif arg == 'whois_check': params['whois_check'] = True
            
            module_instance = current_app.agent_instance.get_module_instance(
                module_name, current_session_id, project_name
            )
            if not module_instance:
                error_message = f"Failed to get instance for module: {module_name}."
                logger.error(error_message)
                return jsonify({
                    "status": "error",
                    "message": _format_text_for_html_display(error_message),
                    "response_for_ui": _format_text_for_html_display(error_message),
                    "user_command": command_string,
                    "module_name": module_name,
                    "target": params.get('target', 'N/A'),
                    "ports": params.get('ports', 'N/A'),
                    "structured_results": {},
                    "raw_output": _format_text_for_html_display(error_message),
                    "error_output": error_message,
                    "exit_code": 1,
                    "llm_analysis": _format_text_for_html_display(f"LLM analysis not applicable due to module error: {error_message}")
                })

            logger.info(f"Executing module {module_name} with params: {params}")
            result = module_instance.run(params)

            status = result.get('status', 'error')
            message = result.get('message', 'Module execution failed.')
            raw_output = result.get('raw_output', '')
            structured_results = result.get('structured_results', {})
            
            llm_analysis = _format_text_for_html_display("LLM analysis skipped: No raw output or module failed.")
            if Config.LLM_API_URL and status in ['success', 'warning'] and (raw_output or structured_results):
                try:
                    llm_input_prompt = f"""
                    You are a highly experienced and concise cybersecurity analyst, specializing in penetration testing.
                    Your goal is to provide **technical, actionable, and focused analysis** of a single command's output.

                    **Focus on:**
                    1.  **Key Finding(s):** The most significant discovery or implication (1-2 sentences).
                    2.  **Technical Risk/Impact:** What does this finding mean for the target's security? (e.g., "Potential RCE," "Information Leakage").
                    3.  **Severity:** (Low, Medium, High, Critical) - based on the technical impact.
                    4.  **Concise Remediation:** Specific, actionable steps to mitigate the identified risk. Avoid generic advice.
                    5.  **Further Manual Testing:** Specific manual tests a human pentester should conduct next to validate or exploit this finding.

                    **Output Format:**
                    Start directly with the "Key Finding(s):" and use concise bullet points for the rest. Do NOT include greetings or extraneous information.

                    ---
                    Command: {command_string}
                    Module: {module_name}
                    Target: {params.get('target', 'N/A')}
                    Ports: {params.get('ports', 'N/A')}

                    Raw Output:
                    {raw_output}

                    Structured Results (JSON):
                    {json.dumps(structured_results, indent=2)}
                    ---
                    """
                    llm_analysis = current_app.agent_instance._call_llm_api(llm_input_prompt)

                    if 'LLM analysis skipped' in llm_analysis or 'Request timed out' in llm_analysis or 'LLM analysis failed' in llm_analysis:
                        logger.warning(f"LLM analysis failed/skipped for command '{command_string}': {llm_analysis}")
                    else:
                        logger.info(f"LLM analysis successfully generated for command '{command_string}'.")

                except Exception as e:
                    logger.error(f"Error during LLM analysis generation: {e}", exc_info=True)
                    llm_analysis = _format_text_for_html_display(f"LLM analysis failed: Error during processing: {e}")
            elif not Config.LLM_API_URL:
                llm_analysis = _format_text_for_html_display("LLM_API_URL not configured. LLM analysis skipped.")


            final_response = {
                'status': status,
                'message': message, 
                'response_for_ui': _format_text_for_html_display(message), 
                'user_command': command_string,
                'module_name': module_name,
                'target': params.get('target', 'N/A'),
                'ports': params.get('ports', 'N/A'),
                'structured_results': structured_results,
                'raw_output': _format_text_for_html_display(raw_output),
                'error_output': _format_text_for_html_display(result.get('error_output', '')),
                'exit_code': result.get('exit_code', 0 if status == 'success' else 1),
                'llm_analysis': llm_analysis
            }
            
            save_command_result(project_id, current_session_id, command_string, module_name, 
                                params.get('target', 'N/A'), status, message, structured_results, 
                                raw_output, llm_analysis)
            logger.info(f"Command result saved for session {current_session_id}.")

            return jsonify(final_response)

        else: # Catch-all for unknown commands after ask_ai/help
            error_message = f"Unknown module: {module_name}. Supported modules: network_discovery, ip_scan, osint, ask_ai, help."
            logger.error(error_message)
            return jsonify({
                "status": "error",
                "message": _format_text_for_html_display(error_message),
                "response_for_ui": _format_text_for_html_display(error_message),
                "user_command": command_string,
                "module_name": module_name,
                "target": "N/A",
                "ports": "N/A",
                "structured_results": {},
                "raw_output": _format_text_for_html_display(error_message),
                "error_output": error_message,
                "exit_code": 1,
                "llm_analysis": _format_text_for_html_display(f"LLM analysis not applicable due to module error: {error_message}")
            })

    except Exception as e:
        logger.error(f"Error processing command '{command_string}' for session {current_session_id}: {e}", exc_info=True)
        return jsonify({
            "response": _format_text_for_html_display(f"An unexpected error occurred during command processing: {e}"),
            "message": _format_text_for_html_display(str(e)),
            "status": "error"
        }), 500


# --- Generate Project Report Route ---
@app.route('/generate_project_report/<project_id>', methods=['GET'])
@login_required
def generate_project_report(project_id):
    user_id = session.get('user_id')

    conn = get_db()
    cursor = conn.cursor()

    # Verify project belongs to user
    cursor.execute("SELECT id, name FROM projects WHERE id = ? AND user_id = ?", (project_id, user_id))
    project = cursor.fetchone()
    if not project:
        return jsonify({'status': 'error', 'message': 'Project not found or unauthorized.'}), 404

    project_name = project['name']

    # Fetch all command history for this project, including timestamps
    cursor.execute("SELECT user_command, llm_analysis, timestamp FROM command_history WHERE project_id = ? ORDER BY timestamp ASC", (project_id,))
    history_entries = cursor.fetchall()

    consolidated_analyses = []
    executed_tests = []
    
    min_timestamp = None
    max_timestamp = None

    if not history_entries:
        report_content = _format_text_for_html_display("No command history with LLM analysis found for this project to generate a report.")
        return jsonify({
            'status': 'success',
            'project_name': project_name,
            'report_content': report_content
        })

    for entry in history_entries:
        # Update min/max timestamps
        current_ts = datetime.fromisoformat(entry['timestamp'])
        if min_timestamp is None or current_ts < min_timestamp:
            min_timestamp = current_ts
        if max_timestamp is None or current_ts > max_timestamp:
            max_timestamp = current_ts

        # Collect LLM analyses for consolidation
        if entry['llm_analysis'] and entry['llm_analysis'] != 'N/A':
            # Convert HTML <br> back to newlines for LLM prompt context
            markdown_analysis = entry['llm_analysis'].replace('<br><br>', '\n\n').replace('<br>', '\n')
            consolidated_analyses.append(f"--- Command: {entry['user_command']} ---\n{markdown_analysis}\n")
        else:
            consolidated_analyses.append(f"--- Command: {entry['user_command']} (No LLM analysis available) ---\n")
        
        # Collect executed test types
        executed_tests.append(f"- `{entry['user_command']}`")

    combined_analysis_text = "\n\n".join(consolidated_analyses)
    summary_of_tests = "\n".join(executed_tests)

    # Format timestamps for the report
    report_start_time = min_timestamp.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if min_timestamp else "N/A"
    report_end_time = max_timestamp.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if max_timestamp else "N/A"

    # --- Project Report Generation Prompt ---
    report_prompt = f"""
    You are a highly experienced and professional cybersecurity penetration testing lead.
    Your task is to compile a comprehensive, concise, and actionable security assessment report for the project '{project_name}'.
    The report should synthesize all individual command analyses into a clear, executive-level summary with technical details and prioritized remediation steps.

    **Report Structure (Strictly adhere to this format):**

    ## 1. Executive Summary
    Provide a concise (2-3 sentences) high-level overview of the penetration testing activities and the most critical findings. Highlight any 'Critical' or 'High' severity vulnerabilities immediately.

    **Testing Period:**
    - Start: {report_start_time}
    - End: {report_end_time}

    **Tests Performed:**
    A brief summary of the types of scans and OSINT activities conducted:
    {summary_of_tests}

    ## 2. Overall Findings Summary
    Summarize the overall security posture based on all executed tests. Include general observations about the target environment.

    ## 3. Vulnerability Categorization and Impact
    Categorize all identified vulnerabilities by type (e.g., Open Ports, Information Disclosure, Misconfiguration, Weak Authentication, Vulnerable OS/Service).
    For each category:
    - List specific findings (e.g., "SSH Port 22 Open (Target: 192.168.1.51)")
    - Describe the technical impact/risk (e.g., "Potential for brute-force attack, unauthorized access")
    - Assign a clear severity (Low, Medium, High, Critical)

    Example format:
    ### Open Ports
    - **Finding:** Port 80 (HTTP) open on 192.168.1.100 running Apache 2.4.
      - **Impact:** Potential for web application vulnerabilities, information leakage.
      - **Severity:** Medium
    - **Finding:** Port 22 (SSH) open on 192.168.1.50.
      - **Impact:** Brute-force attacks, unauthorized shell access.
      - **Severity:** High

    ## 4. Prioritized Recommendations (Remediation Plan)
    Provide clear, actionable, and prioritized remediation steps.

    ### Do Now (Critical & High Severity)
    - Immediate actions for critical vulnerabilities.

    ### Do Soon (Medium Severity)
    - Actions to take within a short timeframe.

    ### Do Later (Low Severity / Best Practices)
    - Long-term improvements and general security hardening.

    ## 5. Further Manual Penetration Testing & Future Steps
    Suggest specific manual tests or deeper dives a human penetration tester should conduct based on the automated findings. Also, propose ongoing security practices or future assessments.

    --- Raw Automated Analysis Data (for context, do not just copy-paste) ---
    {combined_analysis_text}
    """
    
    logger.debug(f"Report Generation LLM Prompt (first 500 chars):\n{report_prompt[:500]}...")

    try:
        llm_report_content = current_app.agent_instance._call_llm_api(report_prompt)

        return jsonify({
            'status': 'success',
            'project_name': project_name,
            'report_content': llm_report_content
        })
    except Exception as e:
        logger.error(f"Error generating project report for project {project_id}: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f"Failed to generate report: {e}",
            'report_content': _format_text_for_html_display(f"Failed to generate report due to an internal error: {e}")
        }), 500


# --- Main Execution ---
if __name__ == '__main__':
    # Initialize the database when the app starts
    with app.app_context():
        init_db()

        app.agent_instance = AIAgent(modules_dict={
            'network_discovery': NetworkDiscoveryModule,
            'ip_scan': IPScanModule,
            'osint': OSINTModule
        })

    app.run(debug=True, host='0.0.0.0')