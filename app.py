from flask import Flask, render_template, request, redirect, session, url_for, flash
from forms import UserForm, SmsForm
from random import randint
import time
import os
import ldap
import requests
import json


app = Flask(__name__)
app.secret_key = os.environ['FLASKSECRETKEY']

AD_FQDN = os.environ['ADFQDN']
AD_USER = os.environ['ADUSER']
AD_PASS = os.environ['ADPASS']

ERP_APIKEY = os.environ['ERPAPIKEY']
ERP_URL = os.environ['ERPURL']
ERP_HEADERS = {
    'api-key': '{}'.format(ERP_APIKEY)
}

PS7000_URL = os.environ['PS7000URL']
PS7000_APIKEY = os.environ['PS7000APIKEY']

PS7000_HEADERS = {
    'Authorization': "Basic {}".format(PS7000_APIKEY)
}

SMS_API_URL = os.environ['SMSAPIURL']
SMS_USER_PASS = os.environ['SMSUSERPASS']

# disable certificate verification
requests.packages.urllib3.disable_warnings()


def generate_sms_code():
    return randint(100000, 999999)


def get_employee_id(username: str) -> str:
    '''

    :param username: str
    :return: str
    '''
    ldap_conn = ldap.initialize('ldap://{}'.format(AD_FQDN.lower()))
    ad_domain = AD_FQDN.split(".")[0]
    ldap_conn.simple_bind_s(ad_domain + "\\" + AD_USER, AD_PASS)
    ldap_conn.set_option(ldap.OPT_REFERRALS, 0)

    ad_fqdn_list = AD_FQDN.lower().split('.')
    baseDN_list = []

    for item in ad_fqdn_list:
        baseDN_list.append("dc={}".format(item))

    baseDN = ",".join(baseDN_list)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = ['employeeID']
    searchFilter = "sAMAccountName={}".format(username)

    result = ldap_conn.search_s(baseDN, searchScope, searchFilter, retrieveAttributes)

    if result[0][0]:
        employee_id = result[0][-1]['employeeID'][0].decode("utf-8")
        return employee_id
    else:
        return False


def get_phone_number(employee_id):
    full_erp_url = ERP_URL + "{}".format(employee_id)
    response = requests.request("GET", full_erp_url, headers=ERP_HEADERS, verify=False)
    response_dict = json.loads(response.text)
    phone_number = response_dict['privateMobileNumber']
    phone_number = "".join(phone_number.split(" ")[-2:]).replace("(", "").replace(")", "")
    return phone_number


def verify_user(username, phone_number):
    employee_id = get_employee_id(username)
    if employee_id:
        erp_phone_number = get_phone_number(employee_id)
    else:
        return False

    if erp_phone_number == phone_number:
        return True
    else:
        return False


def send_sms(phone_number):
    sms_code = generate_sms_code()
    session['time_when_generated'] = int(time.time())
    session['sms_code_in_session'] = str(sms_code)
    url = SMS_API_URL
    return True
#    user_pass_list = SMS_USER_PASS.split(',')
#
#    payload = "<SingleTextSMS> <UserName>{}</UserName> <PassWord>{}</PassWord> <Action>0</Action> " \
#              "<Mesgbody>OTP Reset/Unlock Code: {}</Mesgbody> <Numbers>{}</Numbers> " \
#              "</SingleTextSMS>".format(user_pass_list[0], user_pass_list[1], str(sms_code), phone_number)
#
#    response = requests.request("POST", url, data=payload)
#
#    if "ID" in response.text:
#        return True
#    else:
#        return False


def unlock_vpn_otp(username):
    url = "{}{}?operation=unlock".format(PS7000_URL, username)
    response = requests.request("PUT", url, headers=PS7000_HEADERS, verify=False)
    response_dict = json.loads(response.text)
    if response.status_code == 200:
        msg = response_dict['result']['info'][0]['message']
        return msg
    elif response.status_code == 400:
        msg = response_dict['result']['errors'][0]['message']
        return msg
    else:
        return "Unknown"


def reset_vpn_otp(username):
    url = "{}{}?operation=reset".format(PS7000_URL, username)
    response = requests.request("PUT", url, headers=PS7000_HEADERS, verify=False)
    response_dict = json.loads(response.text)
    if response.status_code == 200:
        msg = response_dict['result']['info'][0]['message']
        return msg
    elif response.status_code == 400:
        msg = response_dict['result']['errors'][0]['message']
        return msg
    else:
        return "Unknown Failure! Contact Administrator"


@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    form = UserForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            username = request.form['input_username']
            phone_number = request.form['input_phone_number']

            user_is_verified = verify_user(username, phone_number)
            if user_is_verified:
                session['username'] = username
                sms_is_sent = send_sms(phone_number)
                if sms_is_sent:
                    session['reset'] = False  # account is to be unlocked
                    return redirect(url_for('sms_code_input'))
                else:
                    flash("SMS Code Sending Failed, try again later!")
            else:
                flash("Username or Phone Number is Incorrect! Try Again!", "danger")
    # else:
    #     session.pop('_flashes', None)

    return render_template('unlock_form.html', form=form)


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    form = UserForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            username = request.form['input_username']
            phone_number = request.form['input_phone_number']

            user_is_verified = verify_user(username, phone_number)
            if user_is_verified:
                session['username'] = username
                sms_is_sent = send_sms(phone_number)
                if sms_is_sent:
                    session['reset'] = True
                    return redirect(url_for('sms_code_input'))
                else:
                    flash("SMS Code Sending Failed, try again later!", "danger")
            else:
                flash("Username or Phone Number is Incorrect! Try Again!", "danger")

    return render_template('reset_form.html', form=form)


@app.route('/sms_code_input', methods=['GET', 'POST'])
def sms_code_input():
    form = SmsForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            if 'sms_code_in_session' in session:
                current_time = int(time.time())
                if current_time - session['time_when_generated'] < 120:
                    sms_input_from_user = request.form['input_sms_code']
                    if sms_input_from_user == session['sms_code_in_session']:
                        print("SUCCESS!")
                        if session['reset']:
                            vpn_api_call_result = reset_vpn_otp(session['username'])
                        else:
                            vpn_api_call_result = unlock_vpn_otp(session['username'])

                        # User Feedback Message:
                        if "Error" in vpn_api_call_result:
                            flash_cat = "danger"
                        elif "Unknown Failure" in vpn_api_call_result:
                            flash_cat = "warning"
                        elif "is not present" in vpn_api_call_result:
                            flash_cat = "warning"
                        else:
                            flash_cat = "success"
                        flash(vpn_api_call_result, flash_cat)
                        #
                        print("User input: {}".format(sms_input_from_user))
                        print("Generated: {}".format(session['sms_code_in_session']))
                        session.pop('sms_code_in_session', None)
                    else:
                        flash('Wrong SMS Code!', "danger")
                        print("User input: {}".format(sms_input_from_user))
                        print("Generated: {}".format(session['sms_code_in_session']))
                        print("FAIL!")
                else:
                    flash('SMS is no longer valid; return previous page!', "danger")
                    session.pop('sms_code_in_session', None)

            else:
                if session['reset']:
                    return redirect(url_for('reset'))
                else:
                    return redirect(url_for('unlock'))
        else:
            flash("Enter code with valid length!", "warning")

    return render_template('sms_code_input.html', form=form)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
