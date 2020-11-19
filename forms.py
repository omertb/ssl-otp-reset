from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired, Length, Regexp


class UserForm(FlaskForm):
    on_behalf_option = SelectField('on_behalf_of_option', choices=["Myself", "Third Party User"])
    input_username = StringField('input_username',
                                 validators=[DataRequired(), Length(min=5, max=128),
                                             Regexp('^[A-Za-z0-9\.]+$', message="Invalid characters in username!")])
    input_phone_number = StringField('input_phone_number', validators=[DataRequired(), Length(min=10)])
    third_party_user = StringField('third_party_username',
                                   validators=[Regexp('^[A-Za-z0-9\.]*$', message="Invalid characters in username!")])
    recaptcha = RecaptchaField()


class SmsForm(FlaskForm):
    input_sms_code = StringField('sms_code', validators=[DataRequired(), Length(min=6, max=6)])
