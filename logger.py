from logging.handlers import SysLogHandler
import logging
from time import gmtime, strftime
import os
# import socket


LOG_SERVER = "10.29.6.10"
DATE_FORMAT = "[%a, %d/%b/%Y %H:%M:%S +0000]"
NAME_FORMAT = "%Y%m%d.log"
LOG_DIR = "/project/logs/"


class ContextFilter(logging.Filter):
    # hostname = socket.gethostname()
    hostname = "meranet-flask-server"

    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True


def send_wr_log(log_message):
    if LOG_SERVER:
        syslogger = logging.getLogger('SyslogLogger')
        syslogger.setLevel(logging.INFO)
        log_handler = SysLogHandler(address=(LOG_SERVER, 5044))
        log_handler.addFilter(ContextFilter())
        msg_format = '%(asctime)s %(hostname)s  %(message)s'
        formatter = logging.Formatter(msg_format, datefmt='%b %d %H:%M:%S')
        log_handler.setFormatter(formatter)
        syslogger.addHandler(log_handler)
        syslogger.info(log_message)

    # write to a log file
    log_date = strftime(DATE_FORMAT, gmtime())
    log_line = "{} - {}".format(log_date, log_message)
    log_filename = "{}{}".format(LOG_DIR, strftime(NAME_FORMAT, gmtime()))
    os.makedirs(os.path.dirname(log_filename), exist_ok=True)
    with open(log_filename, "a") as f:
        f.write("\n" + log_line)