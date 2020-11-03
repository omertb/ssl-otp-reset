from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField
from wtforms.validators import DataRequired, Length, Regexp


class UserForm(FlaskForm):
    input_username = StringField('input_username',
                                 validators=[DataRequired(), Length(min=5, max=128),
                                             Regexp('^[a-z0-9\.]+$', message="Invalid characters in username!")])
    input_phone_number = StringField('input_phone_number', validators=[DataRequired(), Length(min=10)])
    recaptcha = RecaptchaField()


class SmsForm(FlaskForm):
    input_sms_code = StringField('sms_code', validators=[DataRequired(), Length(min=6, max=6)])
