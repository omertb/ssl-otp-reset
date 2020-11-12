from flask import Flask, render_template, request, redirect, session, url_for, flash, Markup
from forms import UserForm, SmsForm
from random import randint
from logger import send_wr_log
import time
from time import gmtime, strftime
import os
import ldap, ldap.dn, ldap.filter
import requests
import json
import pdb

app = Flask(__name__)
app.secret_key = os.environ['FLASKSECRETKEY']

# session header options:
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Google ReCaptcha Keys:
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ['CAPTCHAPUBKEY']
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ['CAPTCHAPRIKEY']
app.config['RECAPTCHA_USE_SSL']= False

# Active Directory Access (to get employee id):
AD_FQDN = os.environ['ADFQDN']
AD_USER = os.environ['ADUSER']
AD_PASS = os.environ['ADPASS']

# Corporate ERP System Access, (for user-phone validation)
ERP_APIKEY = os.environ['ERPAPIKEY']
ERP_URL = os.environ['ERPURL']
ERP_HEADERS = {
    'api-key': '{}'.format(ERP_APIKEY)
}

# ssl-vpn server api access
PS7000_URL = os.environ['PS7000URL']
PS7000_APIKEY = os.environ['PS7000APIKEY']
PS7000_HEADERS = {
    'Authorization': "Basic {}".format(PS7000_APIKEY)
}

# cell network api access to send sms:
SMS_API_URL = os.environ['SMSAPIURL']
SMS_USER_PASS = ""  # decision made in get_phone_number function

# disable certificate verification
requests.packages.urllib3.disable_warnings()

sms_error_dict = {
    '1': "invalid credential",
    '2': "account in debit",
    '3': "invalid action element",
    '5': "xml error",
    '6': "invalid originator element",
    '7': "message id not found",
    '9': "invalid date",
    '10': "sms not sent"
}


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
        baseDN_list.append("dc={}".format(ldap.dn.escape_dn_chars(item)))

    baseDN = ",".join(baseDN_list)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = ['employeeID']
    searchFilter = "sAMAccountName={}".format(ldap.filter.escape_filter_chars(username))

    result = ldap_conn.search_s(baseDN, searchScope, searchFilter, retrieveAttributes)

    if result[0][0]:
        try:
            employee_id = result[0][-1]['employeeID'][0].decode("utf-8")
        except KeyError:
            # flash("employeeID is missing in Active Directory!\n Contact IT System and Datacenter Management.", "danger")
            return False
        return employee_id
    else:
        return False


def get_ldap_user(username: str) -> str:
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
        baseDN_list.append("dc={}".format(ldap.dn.escape_dn_chars(item)))

    baseDN = ",".join(baseDN_list)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = ['']
    searchFilter = "sAMAccountName={}".format(ldap.filter.escape_filter_chars(username))

    result = ldap_conn.search_s(baseDN, searchScope, searchFilter, retrieveAttributes)

    return result[0][0]


def get_phone_number(employee_id):
    full_erp_url = ERP_URL + "{}".format(employee_id)
    response = requests.request("GET", full_erp_url, headers=ERP_HEADERS, verify=False)
    response_dict = json.loads(response.text)
    phone_number = response_dict['privateMobileNumber']

    phone_number = phone_number.replace("(", "").replace(")", "")
    phone_number_parts = phone_number.split(" ")

    global SMS_USER_PASS

    if phone_number_parts[0] == "0090" or phone_number_parts[0] == "90":
        SMS_USER_PASS = os.environ['SMSUSERPASS'].split(',')
        phone_number = "".join(phone_number_parts[-2:])
    else:
        SMS_USER_PASS = os.environ['SMSUSERPASSINT'].split(',')
        if not phone_number_parts[0].startswith("00"):
            phone_number_parts[0] = "00" + phone_number_parts[0]
        phone_number = "".join(phone_number_parts)

    return phone_number


def verify_user(username, phone_number):
    session['erp_phone_number'] = None
    # return True  # troubleshooting purpose
    employee_id = get_employee_id(username)
    if employee_id:
        erp_phone_number = get_phone_number(employee_id)
        session['erp_phone_number'] = erp_phone_number
    else:
        return False

    if erp_phone_number == phone_number:
        return True
    else:
        return False


def check_sms_count(phone_number):
    DIR = "/project/sms_count/"
    NAME_FORMAT = "%Y%m%d.log"
    log_filename = "{}{}".format(DIR, strftime(NAME_FORMAT, gmtime()))
    os.makedirs(os.path.dirname(log_filename), exist_ok=True)

    with open(log_filename, "a") as f:
        f.write("{}\n".format(phone_number))

    with open(log_filename, "r") as f:
        numbers_str = f.read()
    numbers_list = numbers_str.splitlines()
    if numbers_list.count(phone_number) > 5:
        return False
    else:
        return True


def send_sms(phone_number):
    sms_code = generate_sms_code()
    session['time_when_generated'] = int(time.time())
    session['sms_code_in_session'] = str(sms_code)
    user_pass_list = SMS_USER_PASS  # set under get_phone_number as global variable
    url = SMS_API_URL

    payload = "<SingleTextSMS> <UserName>{}</UserName> <PassWord>{}</PassWord> <Action>0</Action> " \
              "<Mesgbody>OTP Reset/Unlock Code: {}</Mesgbody> <Numbers>{}</Numbers> " \
              "</SingleTextSMS>".format(user_pass_list[0], user_pass_list[1], str(sms_code), phone_number)

    response = requests.request("POST", url, data=payload)

    if "ID" in response.text:
        message = "Sent SMS to phone number: {} with ID Number: {}".format(phone_number, response.text)
        send_wr_log(message)
        return True
    else:
        message = "Failed to send SMS to phone number: {}; Error Code: {}, {}".format(phone_number, response.text,
                                                                                      sms_error_dict[response.text])
        send_wr_log(message)
        return False


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

        time.sleep(2)
        session['input_count'] = 0
        # sms_code_in_session control
        # if 'sms_code_in_session' in session:
        #     session.pop('sms_code_in_session', None)
        if form.validate_on_submit():
            username = request.form['input_username']
            username = username.split('@')[0]
            username = username.split("\\")[-1]
            phone_number = request.form['input_phone_number']

            try:
                user_is_verified = verify_user(username, phone_number)
            except ldap.LDAPError as e:
                flash("LDAP Error: {}".format(e), "danger")
                return render_template('unlock_form.html', form=form)
            except json.decoder.JSONDecodeError as e:
                flash("JSON Error: {}".format(e), "danger")
                return render_template('unlock_form.html', form=form)
            except requests.exceptions.ConnectionError as e:
                flash("URL Connection Error", "danger")
                return render_template('unlock_form.html', form=form)

            # logging:
            message = "User: {} - Phone Number: {}, ERP Phone: {}, " \
                      "LDAP-ERP Verification: {}".format(username, phone_number,
                                                         session['erp_phone_number'],
                                                         "SUCCESS" if user_is_verified else "FAIL")
            send_wr_log(message)

            if user_is_verified:
                on_behalf_option = request.form['on_behalf_option']
                # unlock for myself
                if on_behalf_option == "Myself":
                    below_limit = check_sms_count(phone_number)
                    if not below_limit:
                        message = "You cannot send more than 5 SMS per day. Please contact to 1818"
                        send_wr_log("User: {} - {}".format(username, message))
                        flash(message, "danger")
                        return render_template('unlock_form.html', form=form)

                    session['username'] = username

                # unlock for someone else, 3rd party user
                else:
                    third_party_user = request.form['third_party_user']
                    third_party_user = third_party_user.split('@')[0]
                    third_party_user = third_party_user.split("\\")[-1]
                    try:
                        third_party_user_ldap_dn = get_ldap_user(third_party_user)
                        username_ldap_dn = get_ldap_user(username)
                    except ldap.LDAPError as e:
                        flash("LDAP Error: {}".format(e), "danger")
                        return render_template('unlock_form.html', form=form)

                    if not third_party_user_ldap_dn:
                        # if user is not found, misinform form submitter
                        flash("Not authorized!", "warning")
                        log_msg = "User: {} - Unlock attempt on non-existing user {}".format(username, third_party_user)
                        send_wr_log(log_msg)
                        return render_template('unlock_form.html', form=form)

                    # only these groups can unlock only 3rd party users
                    if ("OU=BT MAGAZA DESTEK MUDURLUGU" in username_ldap_dn \
                            or "OU=BT MERKEZ DESTEK-DEPO-LISANS MUDURLUGU" in username_ldap_dn)\
                            and "OU=THIRD PARTY" in third_party_user_ldap_dn:
                        session['username'] = third_party_user
                        log_msg = "User: {} - Unlock attempt on user {}".format(username, third_party_user)
                        send_wr_log(log_msg)
                    else:
                        flash("Not authorized!", "warning")
                        log_msg = "User: {} - Not authorized to unlock user {}".format(username, third_party_user)
                        send_wr_log(log_msg)
                        return render_template('unlock_form.html', form=form)

                # send sms to the person performing unlock
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
        session['input_count'] = 0
        # sms_code_in_session control
        # if 'sms_code_in_session' in session:
        #     session.pop('sms_code_in_session', None)
        if form.validate_on_submit():
            username = request.form['input_username']
            username = username.split('@')[0]
            username = username.split("\\")[-1]
            phone_number = request.form['input_phone_number']

            try:
                user_is_verified = verify_user(username, phone_number)
            except ldap.LDAPError as e:
                flash("LDAP Error: {}".format(e), "danger")
                return render_template('reset_form.html', form=form)
            except json.decoder.JSONDecodeError as e:
                flash("JSON Error: {}".format(e), "danger")
                return render_template('reset_form.html', form=form)
            except requests.exceptions.ConnectionError as e:
                flash("URL Connection Error", "danger")
                return render_template('reset_form.html', form=form)

            # logging:
            message = "User: {} - Phone Number: {}, ERP Phone: {}, " \
                      "LDAP-ERP Verification: {}".format(username, phone_number,
                                                         session['erp_phone_number'],
                                                         "SUCCESS" if user_is_verified else "FAIL")
            send_wr_log(message)

            if user_is_verified:
                on_behalf_option = request.form['on_behalf_option']
                # reset for myself
                if on_behalf_option == "Myself":
                    below_limit = check_sms_count(phone_number)
                    if not below_limit:
                        message = "You cannot send more than 5 SMS per day. Please contact to 1818"
                        send_wr_log("User: {} - {}".format(username, message))
                        flash(message, "danger")
                        return render_template('reset_form.html', form=form)

                    session['username'] = username

                # reset for someone else, 3rd party user
                else:
                    third_party_user = request.form['third_party_user']
                    third_party_user = third_party_user.split('@')[0]
                    third_party_user = third_party_user.split("\\")[-1]
                    try:
                        third_party_user_ldap_dn = get_ldap_user(third_party_user)
                        username_ldap_dn = get_ldap_user(username)
                    except ldap.LDAPError as e:
                        flash("LDAP Error: {}".format(e), "danger")
                        return render_template('reset_form.html', form=form)

                    if not third_party_user_ldap_dn:
                        # if user is not found, misinform form submitter
                        flash("Not authorized!", "warning")
                        log_msg = "User: {} - Reset attempt on non-existing user {}".format(username, third_party_user)
                        send_wr_log(log_msg)
                        return render_template('reset_form.html', form=form)

                    # only these groups can unlock only 3rd party users
                    if ("OU=BT MAGAZA DESTEK MUDURLUGU" in username_ldap_dn \
                            or "OU=BT MERKEZ DESTEK-DEPO-LISANS MUDURLUGU" in username_ldap_dn)\
                            and "OU=THIRD PARTY" in third_party_user_ldap_dn:
                        session['username'] = third_party_user
                        log_msg = "User: {} - Reset attempt on user {}".format(username, third_party_user)
                        send_wr_log(log_msg)
                    else:
                        flash("Not authorized!", "warning")
                        log_msg = "User: {} - Not authorized to reset user {}".format(username, third_party_user)
                        send_wr_log(log_msg)
                        return render_template('reset_form.html', form=form)

                # send sms to the person performing reset
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
                session['input_count'] += 1
                if session['input_count'] == 4:
                    flash('SMS code is invalid, try again!', "warning")
                    session.pop('sms_code_in_session', None)
                    if session['reset']:
                        return redirect(url_for('reset'))
                    else:
                        return redirect(url_for('unlock'))
                if current_time - session['time_when_generated'] < 120:
                    sms_input_from_user = request.form['input_sms_code']
                    if sms_input_from_user == session['sms_code_in_session']:
                        message = "User: {} - SMS Code Verification: SUCCESS".format(session['username'])
                        send_wr_log(message)

                        if session['reset']:
                            vpn_api_call_result = reset_vpn_otp(session['username'])
                        else:
                            vpn_api_call_result = unlock_vpn_otp(session['username'])

                        flash_message = vpn_api_call_result
                        # User Feedback Message:
                        if "Error" in vpn_api_call_result:
                            flash_cat = "danger"
                        elif "Unknown Failure" in vpn_api_call_result:
                            flash_cat = "warning"
                        elif "is not present" in vpn_api_call_result:
                            flash_cat = "warning"
                        else:
                            flash_cat = "success"
                            if session['reset']:
                                link_msg = Markup('<p>Get a new QR code on <a href="https://vpn.lcwaikiki.com">vpn.lcwaikiki.com</a></p>')
                                flash_message += "; " + link_msg
                        message = "User: {} - Pulse Secure Response: {}".format(session['username'], vpn_api_call_result)
                        send_wr_log(message)
                        flash(flash_message, flash_cat)
                        session.pop('sms_code_in_session', None)
                    else:
                        flash('Wrong SMS Code!', "danger")
                        message = "User: {} - SMS Code Verification: FAILED".format(session['username'])
                        send_wr_log(message)
                else:
                    flash('Failure! SMS is no longer valid; returned previous page!', "danger")
                    message = "User: {} - SMS Code Timeout".format(session['username'])
                    send_wr_log(message)
                    session.pop('sms_code_in_session', None)
                    time.sleep(5)
                    if session['reset']:
                        return redirect(url_for('reset'))
                    else:
                        return redirect(url_for('unlock'))

            else:
                flash("Returned {} page!".format("reset" if session['reset'] else "unlock"), "warning")
                if session['reset']:
                    return redirect(url_for('reset'))
                else:
                    return redirect(url_for('unlock'))
        else:
            flash("Enter code with valid length!", "warning")

    return render_template('sms_code_input.html', form=form)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
