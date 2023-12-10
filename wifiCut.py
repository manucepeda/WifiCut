from flask import Flask, render_template, request, redirect
from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField, BooleanField, TimeField
from io import StringIO
from logging import StreamHandler
from arp_spoof import ARPSpoofer, log_and_exit
from nmap_scanning import run_initial_nmap_scan, parse_nmap_output, get_device_name, parse_device_id, get_schedule_times
from forms import RestrictForm, ScheduleForm
import sys
from network_operations import restrict_connectivity, unrestrict_connectivity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_securely_generated_secret_key'

class LogStreamHandler(StreamHandler):
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

@app.route('/', methods=['GET', 'POST'])
def index():
    global initial_nmap_result

    restrict_form = RestrictForm()
    schedule_form = ScheduleForm()

    # Check if the initial scan has been performed
    if initial_nmap_result is None:
        # Assign the result of run_initial_nmap_scan to initial_nmap_result
        initial_nmap_result = run_initial_nmap_scan()

        # Check if the initial_nmap_result is still None
        if initial_nmap_result is None:
            # Handle the case where the scan failed
            error_message = "Error during the initial Nmap scan."
            return render_template('error.html', error_message=error_message)

    nmap_hosts, nm = initial_nmap_result
    nmap_devices = parse_nmap_output(nmap_hosts, nm) if nmap_hosts else []
    restrict_form.device_choices = [(f"{device['device_name']} ({device['mac']})", f"{device['ip']}_{device['mac']}") for device in nmap_devices]

    # Get the captured logs and pass them to the template
    log_output = log_stream_handler.log_stream.getvalue()

    return render_template('index.html', restrict_form=restrict_form, schedule_form=schedule_form, nmap_devices=nmap_devices, log_output=log_output)


if __name__ == "__main__":
    app.run(debug=True, port=8090)
