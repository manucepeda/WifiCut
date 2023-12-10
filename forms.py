from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField, BooleanField, TimeField

# Define Flask forms
class RestrictForm(FlaskForm):
    device_choices = []
    device_select = SelectField('Select Device', choices=device_choices)
    submit_restrict = SubmitField('Restrict Connectivity')
    submit_unrestrict = SubmitField('Unrestrict Connectivity')

class ScheduleForm(FlaskForm):
    enable_schedule = BooleanField('Enable Schedule')
    start_time = TimeField('Start Time')
    end_time = TimeField('End Time')