"""
wifiCut.py
V1.0
"""

import sys
import os
from io import StringIO
from logging import StreamHandler
from flask import Flask, render_template, request, redirect
from nmap_scanning import run_initial_nmap_scan, parse_nmap_output, save_nmap_result, load_nmap_result, parse_device_id, get_schedule_times
from forms import RestrictForm, ScheduleForm
from network_operations import restrict_connectivity, unrestrict_connectivity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_securely_generated_secret_key'

class LogStreamHandler(StreamHandler):
    """
    Custom LogStreamHandler class
    """
    def __init__(self, stream=None):
        super().__init__(stream or sys.stdout)
        self.log_stream = StringIO()

    def emit(self, record):
        super().emit(record)
        msg = self.format(record)
        self.log_stream.write(msg + '\n')

# Global variables
initial_nmap_result = None
log_stream_handler = LogStreamHandler()
app.logger.addHandler(log_stream_handler)

@app.route('/restrict', methods=['POST'])
def restrict():
    global initial_nmap_result
    form = RestrictForm(request.form)
    ip_address, mac_address = parse_device_id(request.form.get('device_select'))
    
    # Check if the 'enable_schedule' checkbox is checked
    schedule_enabled = request.form.get('enable_schedule') == 'on'
    
    # Get start_time and end_time from the form
    start_time, end_time = get_schedule_times(ScheduleForm(request.form))

    # Run the initial Nmap scan if it hasn't been performed yet
    if initial_nmap_result is None:
        initial_nmap_result = run_initial_nmap_scan()

    restrict_connectivity(ip_address, mac_address, schedule_enabled, start_time, end_time)
    return redirect('/')

@app.route('/unrestrict', methods=['POST'])
def unrestrict():
    form = RestrictForm(request.form)
    ip_address, mac_address = parse_device_id(request.form.get('device_select'))
    
    # Check if the 'enable_schedule' checkbox is checked
    schedule_enabled = request.form.get('enable_schedule') == 'on'
    
    unrestrict_connectivity(ip_address, mac_address, schedule_enabled)
    return redirect('/')

@app.route('/save_nickname', methods=['POST'])
def save_nickname():
    new_nickname = request.form['nickname']
    save_nickname_entry(new_nickname)
    return redirect('/')

def edit_nickname_entry(old_nickname, new_nickname):
    with open('nicknames.txt', 'r', encoding='utf-8') as file:
        lines = file.readlines()
    with open('nicknames.txt', 'w') as file:
        for line in lines:
            if line.strip() == old_nickname:
                file.write(f"{new_nickname}\n")
            else:
                file.write(line)

def save_nickname_entry(nickname):
    with open('nicknames.txt', 'a') as file:
        file.write(f"{nickname}\n")
        
@app.route('/edit_nickname', methods=['POST'])
def edit_nickname():
    old_nickname = request.form['old_nickname']
    new_nickname = request.form['new_nickname']
    edit_nickname_entry(old_nickname, new_nickname)
    return redirect('/')   

def load_nicknames():
    nicknames = []
    nicknames_file_path = 'nicknames.txt'

    if os.path.exists(nicknames_file_path):
        with open(nicknames_file_path, 'r') as file:
            nicknames = [line.strip() for line in file]

    return nicknames

@app.route('/', methods=['GET', 'POST'])
def index():
    
    restrict_form = RestrictForm()
    schedule_form = ScheduleForm()
    
    # Load Nmap results
    nmap_result = load_nmap_result()

    # If Nmap results are not available, perform the initial scan
    if nmap_result is None:
        # Run the initial Nmap scan and save the results
        nmap_result = run_initial_nmap_scan()
        save_nmap_result(nmap_result)

    # Extract information from Nmap results
    nmap_hosts = nmap_result.get("hosts", [])
    nmap_devices = parse_nmap_output(nmap_hosts, {})  # Pass an empty nm object since nm is not used here


    # Get the captured logs and pass them to the template
    log_output = log_stream_handler.log_stream.getvalue()

    # Check if the form is submitted for saving nickname
    if request.method == 'POST' and 'save_nickname' in request.form:
        nickname = request.form['nickname']
        save_nickname(nickname)

    # Load saved nicknames
    saved_nicknames = load_nicknames()

    return render_template('index.html', restrict_form=restrict_form, schedule_form=schedule_form, nmap_devices=nmap_devices, log_output=log_output, saved_nicknames=saved_nicknames)


if __name__ == "__main__":
    app.run(debug=False, port=8090)
