"""
forms.py
This module defines Flask forms for device restriction and scheduling.
"""

from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField, BooleanField, TimeField

class RestrictForm(FlaskForm):
    """
    Form for restricting and unrestricting connectivity for a selected device.
    """
    device_choices = []
    device_select = SelectField('Select Device', choices=device_choices)
    submit_restrict = SubmitField('Restrict Connectivity')
    submit_unrestrict = SubmitField('Unrestrict Connectivity')

class ScheduleForm(FlaskForm):
    """
    Form for enabling schedule and setting start and end times.
    """
    enable_schedule = BooleanField('Enable Schedule')
    start_time = TimeField('Start Time')
    end_time = TimeField('End Time')
