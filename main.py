import itertools
import threading
from flask import Flask, request, jsonify, url_for, render_template, redirect, session
import uuid
from datetime import datetime
import json 
import platform 
import socket
import base64
import hashlib
from Crypto.Hash import MD4


app = Flask("ParrotBox")
app.secret_key = 'your_secret_key'  # Change to a secure random key in production.

# Load credentials from config.json
with open('config.json') as config_file:
    USER_CREDENTIALS = json.load(config_file)

# File to store API keys
API_KEYS_FILE = 'keys.json'
SAVE_FILE = "saves/saves.json"
HASH_FILE = "saves/hashs.json"
HISTORY_FILE = "saves/history.json"
# Initialize keys.json if it doesn't exist
try:
    with open(API_KEYS_FILE, 'r') as file:
        api_keys = json.load(file)
except FileNotFoundError:
    api_keys = []
    with open(API_KEYS_FILE, 'w') as file:
        json.dump(api_keys, file, indent=4)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password.')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Gather device information.
    device_info = {
        'System': platform.system(),
        'Node Name': platform.node(),
        'Release': platform.release(),
        'Version': platform.version(),
        'Machine': platform.machine(),
        'Processor': platform.processor(),
        'Hostname': socket.gethostname(),
        'IP Address': socket.gethostbyname(socket.gethostname())
    }

    # Handle API key generation
    if request.method == 'POST' and 'generate_key' in request.form:
        new_key = str(uuid.uuid4())  # Generate a unique key
        date = str(datetime.now())
        key_data = {
            'key': new_key,
            'created_at': date,
            'device': device_info
        }
        api_keys.append(key_data)
        with open(API_KEYS_FILE, 'w') as file:
            json.dump(api_keys, file, indent=4)

    # Load API keys for display
    with open(API_KEYS_FILE, 'r') as file:
        keys = json.load(file)
    with open(SAVE_FILE, 'r') as file:
        Jobs = json.load(file)
    with open(HASH_FILE, 'r') as file:
        HashList = json.load(file)
    with open(HISTORY_FILE, 'r') as file:
        HistroyList = json.load(file)
        
    return render_template('dashboard.html', device_info=device_info, keys=keys, Jobs=Jobs, HashList=HashList, HistroyList=HistroyList)

@app.route('/delete_key/<key>', methods=['POST'])
def delete_key(key):
    global api_keys
    # Find and remove the key from the list
    api_keys = [k for k in api_keys if k['key'] != key]
    
    # Save the updated keys back to the JSON file
    with open(API_KEYS_FILE, 'w') as file:
        json.dump(api_keys, file, indent=4)

    return redirect(url_for('dashboard'))

@app.route('/delete_job/<int:job_id>', methods=['POST'])
def delete_job(job_id):
    """
    Delete a job by its ID and update the saves.json file.
    """
    date = str(datetime.now())
    try:
        # Load the existing jobs from the SAVE_FILE
        with open(SAVE_FILE, 'r') as file:
            jobs = json.load(file)
        # loads history data
        try:
            with open(HISTORY_FILE, 'r') as f:
                history_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            history_data = []
        # Filter out the job with the given ID
        jobs = [job for job in jobs if job['id'] != job_id]
        # gets history data ID
        history_id = max((d.get("id", 0) for d in history_data), default=0) + 1
        
        history_entry = {
            "id": history_id,
            "type": "Deletion",
            "timestamp": date,
            "auth": "dashboard",
            "ip": str(request.remote_addr),
            "description": f"Job deleted, ID: {job_id}"
         }
        history_data.append(history_entry)
        # Write the updated list back to SAVE_FILE
        with open(SAVE_FILE, 'w') as file:
            json.dump(jobs, file, indent=4)
            
        try:
            with open(HISTORY_FILE, 'w') as file:
                json.dump(history_data, file, indent=4)
        except Exception as e:
            return jsonify({"error": f"Failed to save data: {str(e)}"}), 500
        return redirect(url_for('dashboard'))

    except (FileNotFoundError, json.JSONDecodeError) as e:
        return jsonify({"error": f"Failed to load or update jobs: {str(e)}"}), 500

@app.route('/new_job', methods=['GET', 'POST'])
def new_job():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Process form data
        job_name = request.form['job_name']
        job_description = request.form['job_description']
        
        # Load existing jobs
        try:
            with open(SAVE_FILE, 'r') as file:
                jobs = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            jobs = []
        try:
            with open(HISTORY_FILE, 'r') as file:
                history = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            history = []
        # Calculate the next ID
        next_id = max((job.get("id", 0) for job in jobs), default=0) + 1
        history_id = max((his.get("id", 0) for his in history), default=0) + 1

        # Create the new job entry
        new_job_entry = {
            "id": next_id,
            "type": job_name.upper(),
            "hash": job_description,
            "created_at": str(datetime.now()),
            "auth": "dashboard",
            "ReqDec": "false"
        }
        new_history_entry = {
            "id": next_id,
            "type": job_name.upper(),
            "hash": job_description,
            "timestamp": str(datetime.now()),
            "auth": "dashboard",
            "ip": str(request.remote_addr),
            "description": "New Job Created"
        }
        # Append to the job list and save
        jobs.append(new_job_entry)
        history.append(new_history_entry)
        with open(SAVE_FILE, 'w') as file:
            json.dump(jobs, file, indent=4)
        with open(HISTORY_FILE, 'w') as file:
            json.dump(history, file, indent=4)

        return redirect(url_for('dashboard'))

    return render_template('new_job.html')


@app.route('/run_job/<int:job_id>', methods=['POST'])
def run_job(job_id):
    """
    Run the crack function in a thread for the selected job.
    """
    try:
        with open(SAVE_FILE, 'r') as file:
            jobs = json.load(file)
        
        # Find the job by ID
        job = next((j for j in jobs if j['id'] == job_id), None)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        # Start the cracking process in a separate thread
        def run_crack():
            hash_type = job['type']
            hash_value = job['hash']
            job["status"] = "processing"
            charset = "abcdefghijklmnopqrstuvwxyz0123456789"
            max_length = 6  # Set your preferred max length
            try:
                with open(SAVE_FILE, 'w') as file:
                    json.dump(jobs, file, indent=4)
                print(f"Result saved for job {job_id}")
            except Exception as e:
                print(f"Failed to save result for job {job_id}: {e}")
            result = crack(hash_type, hash_value, charset, max_length)
            print(f"Job {job_id} result: {result}")
            if result:
                job["status"] = "proccessed"
            else:
                job["status"] = "failed"
            # Update the job with the result
            job['value'] = result
            try:
                with open(SAVE_FILE, 'w') as file:
                    json.dump(jobs, file, indent=4)
                print(f"Result saved for job {job_id}")
            except Exception as e:
                print(f"Failed to save result for job {job_id}: {e}")

        threading.Thread(target=run_crack).start()
        return jsonify({"success": True, "message": f"Job {job_id} is running"}), 200

    except (FileNotFoundError, json.JSONDecodeError) as e:
        return jsonify({"error": f"Failed to load jobs: {str(e)}"}), 500



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

################################################################
#
# DECRYPTION
#
################################################################

def crack(hash_type, hash_value, charset="abcdefghijklmnopqrstuvwxyz0123456789", max_length=6):
    if hash_type == "MD5":
        for length in range(1, max_length + 1):
            print(f"Trying passwords of length {length}...")
            for password_tuple in itertools.product(charset, repeat=length):
                password = ''.join(password_tuple)
                # Hash the generated password
                hashed = hashlib.md5(password.encode()).hexdigest()
                if hashed == hash_value:
                    print(f"Hash cracked! Password is: {password}")
                    return password
        print("Password not found within the specified limits.")
        return None
    elif hash_type == "MD4":
        for length in range(1, max_length + 1):
            print(f"Trying passwords of length {length}...")
            for password_tuple in itertools.product(charset, repeat=length):
                password = ''.join(password_tuple)
                # Hash the generated password using MD4
                md4 = MD4.new()
                md4.update(password.encode())
                hashed = md4.hexdigest()
                if hashed == hash_value:
                    print(f"Hash cracked! Password is: {password}")
                    return password
        print("Password not found within the specified limits.")
        return None
    elif hash_type == "SHA2-224":
        return
    elif hash_type == "SHA2-256":
        return
    elif hash_type == "SHA2-384":
        return
    elif hash_type == "SHA2-512":
        return
    elif hash_type == "SHA3-224":
        return
    elif hash_type == "SHA3-256":
        return
    elif hash_type == "SHA3-384":
        return
    elif hash_type == "SHA3-512":
        return
    elif hash_type == "BASE64":
        Chash = base64.b64decode(hash_value).decode("utf-8")
        return Chash
    elif hash_type == "HEX":
        hash_value = hash_value.replace(" ", "")
        result_string = ''.join([chr(int(hash_value[i:i+2], 16)) for i in range(0, len(hash_value), 2)])
        return result_string
    
def hashm(type, message):
   
    if type.upper() == "MD5":
        hash1 = hashlib.md5(message.encode())
        hash2 = hash1.hexdigest()
        return hash2
    elif type.upper() == "BASE64":
        hash2 = message.encode("ascii")
        hash1 =  base64.b64encode(hash2)
        return hash1

################################################################
#
#   API GARBAGE
#
################################################################

@app.route('/api/info')
def info():
    if request.method == "GET":
        return redirect(url_for("login", _external=True))
    if request.method == 'GET':
        data = {
            "version": 1,
            "name": "ParrotBox"
        }
        return jsonify(data)

@app.route('/api/submit', methods=["POST", "GET"])
def submit():
    if request.method == "GET":
        return redirect(url_for("dashboard", _external=True))  # Ensure you return this redirect

    if not request.is_json:
        return jsonify({"error": "Request is not JSON"}), 400  # Return proper HTTP status code
    
    # Load API keys from file
    with open(API_KEYS_FILE, "r") as file:
        keys_data = json.load(file)
    
    # Extract the list of valid keys
    valid_keys = {entry["key"] for entry in keys_data}
    
    data = request.get_json()  # Correct way to get JSON from the request
    
    # Check if the API key is in the request
    api_key = data.get("api_key")  # Assuming the API key is sent in the JSON body
    if not api_key:
        date = str(datetime.now())
        try:
            with open(HISTORY_FILE, 'r') as file:
                request_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            request_data = []

        # Calculate the next id
        request_id = max((entry.get("id", 0) for entry in request_data), default=0) + 1
        request_entry = {
            "id": request_id,
            "type": "Request",
            "timestamp": date,
            "hash": data["hash"],
            "auth": "declined",
            "ip": str(request.remote_addr),
            "description": "Request denied: Missing token."
        }
        edit_json(HISTORY_FILE, request_entry)
        return jsonify({"error": "Missing API token"}), 401
    
    # Validate the API key
    if api_key not in valid_keys:
        date = str(datetime.now())
        try:
            with open(HISTORY_FILE, 'r') as file:
                request_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            request_data = []

        # Calculate the next id
        request_id = max((entry.get("id", 0) for entry in request_data), default=0) + 1
        request_entry = {
            "id": request_id,
            "type": "Request",
            "timestamp": date,
            "hash": data["hash"],
            "auth": "Declined",
            "ip": str(request.remote_addr),
            "description": "Request denied: Invalid token."
        }
        edit_json(HISTORY_FILE, request_entry)
        return jsonify({"error": "Cant authenicate with API token"}), 403
    
    # list of hash types that need to be brute forced/dict attack
    hashbrowns = ["MD5", "MD4"]
    # Process the request if the API key is valid
    if "type" in data and "hash" in data:
        # process the data
        type = data["type"]
        if type in hashbrowns and "length" not in data and "ReqDec" in data:
            return jsonify({"error": f"Length for: {type} has not be specified."}), 500
        
        date = str(datetime.now())
        auth = "token"
        ReqDec = "false"
        dehash = ""
        hashtype = data["type"].upper()
        if "ReqDec" in data:

            ReqDec = "true"
            hashbrown = data["type"].upper()
            if hashtype == "MD4":
                dehash = crack(hashbrown, data["hash"], max_length=data["length"])
            elif hashtype == "MD5":
                dehash = crack(hashbrown, data["hash"], max_length=data["length"])
            elif hashtype == "BASE64":
                dehash = crack(hashbrown, data["hash"])
            elif hashtype == "HEX":
                dehash = crack(hashbrown, data["hash"])
            else:
                return jsonify({"error": f"Hash Not Supported/Found: {hashbrown}"}), 500
        # Load existing data from SAVE_FILE or start with an empty list
        try:
            with open(SAVE_FILE, 'r') as file:
                existing_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_data = []
        try:
            with open(HISTORY_FILE, 'r') as file:
                history_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            history_data = []

        # Calculate the next id
        next_id = max((entry.get("id", 0) for entry in existing_data), default=0) + 1
        history_id = max((entry.get("id", 0) for entry in history_data), default=0) + 1
        if dehash:
            
         new_entry = {
            "id": next_id,
            "type": data["type"].upper(),
            "created_at": date,
            "hash": data["hash"],
            "auth": auth,
            "ReqDec": ReqDec,
            "value": dehash,
            "length": len(dehash),
            "status": "cracked"
         }
        else: 
            new_entry = {
            "id": next_id,
            "type": data["type"].upper(),
            "created_at": date,
            "hash": data["hash"],
            "auth": auth,
            "ReqDec": ReqDec,
            "status": "submitted"
         }
        history_entry = {
            "id": history_id,
            "type": "Submission",
            "timestamp": date,
            "hash": data["hash"],
            "auth": auth,
            "ip": str(request.remote_addr),
            "description": "Hash submitted"
        }

        # Write the updated list back to SAVE_FILE
        edit_json(SAVE_FILE, new_entry)
        edit_json(HISTORY_FILE, history_entry)
        if dehash != "":
         return jsonify({"success": True, "DecHash": dehash, "id": next_id}), 200
        else: 
            return jsonify({"success": True, "id": next_id}), 200
    else:
        return jsonify({"error": "Request does not contain type or hash"}), 400  # Error if fields are missing

@app.route('/api/hash', methods=["POST", "GET"])
def hash():
    data = request.get_json()
    hash_type = data["type"]
    hash_hash = data["hash"]
    enc_hash = hashm(hash_type, hash_hash)
    date = str(datetime.now())
    auth = "token"
    
    try:
            with open(HASH_FILE, 'r') as file:
                existing_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
            existing_data = []
    try:
            with open(HISTORY_FILE, 'r') as f:
                history_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
            history_data = []

    # Calculate the next id
    next_id = max((entry.get("id", 0) for entry in existing_data), default=0) + 1
    history_id = max((d.get("id", 0) for d in history_data), default=0) + 1
        

            
    new_entry = {
            "id": next_id,
            "type": hash_type,
            "created_at": date,
            "hash": str(enc_hash),
            "auth": auth,
         }
    history_entry = {
            "id": history_id,
            "type": "Encryption",
            "timestamp": date,
            "hash": str(enc_hash),
            "auth": auth,
            "ip": str(request.remote_addr),
            "description": "Hash encrypted"
         }

    edit_json(HISTORY_FILE, history_entry)
    edit_json(HASH_FILE, new_entry)

    return jsonify({"DecHash": str(enc_hash)})

def edit_json(FILE,new_entry):
    try:
        with open(FILE, 'r') as file:
            existing_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
            existing_data = []
   
    
    # Append the new entry to the list
    existing_data.append(new_entry)
    try:
        with open(FILE, 'w') as file:
            json.dump(existing_data, file, indent=4)
    except Exception as e:
        return jsonify({"error": f"Failed to save data: {str(e)}"}), 500

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip
if __name__ == '__main__':
    app.run(debug=True, host=str(get_local_ip()))
