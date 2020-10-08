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

    employee_id = result[0][-1]['employeeID'][0].decode("utf-8")

    return employee_id


def get_phone_number(employee_id):
    full_erp_url = ERP_URL + "{}".format(employee_id)
    response = requests.request("GET", full_erp_url, headers=ERP_HEADERS, verify=False)
    response_dict = json.loads(response.text)
    phone_number = response_dict['privateMobileNumber']
    phone_number = "".join(phone_number.split(" ")[-2:]).replace("(", "").replace(")", "")
    return phone_number


def verify_user(username, phone_number):
    employee_id = get_employee_id(username)
    erp_phone_number = get_phone_number(employee_id)
    if erp_phone_number == phone_number:
        return True
    else:
        return False


def send_sms(phone_number):
    sms_code = generate_sms_code()
    session['time_when_generated'] = int(time.time())
    session['sms_code_in_session'] = str(sms_code)
    return True


@app.route('/', methods=['GET', 'POST'])
def home():
    form = UserForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            username = request.form['input_username']
            phone_number = request.form['input_phone_number']

            user_is_verified = verify_user(username, phone_number)
            if user_is_verified:
                sms_is_sent = send_sms(phone_number)
                if sms_is_sent:
                    return redirect(url_for('sms_code_input'))

    return render_template('user_form.html', form=form)


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
                    else:
                        print("FAIL!")
                    print("User input: {}".format(sms_input_from_user))
                    print("Generated: {}".format(session['sms_code_in_session']))
                else:
                    flash('SMS is no longer valid; return previous page!')
                    session.pop('sms_code_in_session', None)
            else:
                return redirect(url_for('home'))

    return render_template('sms_code_input.html', form=form)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
