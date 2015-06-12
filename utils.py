"""Utility module with types difinitions"""
import errno
from namedlist import namedlist

"""HTTP HEADER SPECIFICATION"""
HEADER = namedlist("HEADER", "name delimiter value content default fuzz")
"""HTTP POST DATA SPECIFICATION"""
DATA = namedlist("DATA", "name delimiter value content")
"""HTTP URL SPECIFICATION"""
PATH = namedlist("PATH", "type delimiter name value content")
"""FIRST LINE OF HTTP REQUEST"""
FIRSTLINER = namedlist("FIRSTLINER", "method url version")
"""TASK format"""
HEADER_GEN_MAP = {"Connection":"connection",
                  "Accept-Charset":"acceptcharset",
                  "Accept-Language":"acceptlanguage",
                  "Accept":"accept",
                  "Accept-Encoding":"acceptencoding",
                  "Content-Type":"contenttype",
                  "Range":"range",
                  "Authorization":"basic_auth",
                  }

http_err = "HTTP_ERR"
socket_err = "SOCKET_ERR"
timeout_err = "TIMEOUT_ERR"
def check_response(message):
    if "502" in message or "503" in message:
        return http_err
    if "timed out" in message:
        return timeout_err
    if isinstance(message, Exception):
        if (message.errno == errno.ECONNREFUSED) \
                or (message.errno == errno.ECONNABORTED) \
                or (message.errno == errno.ECONNRESET) \
                or (message.errno == errno.ENETRESET):
            return socket_err

def is_float(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

"""Class describes task being pushed to fuzzing queue"""
class Task(object):

    def __init__(self, iteration=0, param=None, payload=None, task=None, result=None):
        self.current_iteration = iteration
        self.current_fuzzing_parameter = param
        self.current_payload = payload
        self.current_task = task
        self.result = result

    def set_iteration(self, iteration):
        self.current_iteration = iteration

    def set_parameter(self, parameter):
        self.current_fuzzing_parameter = parameter

    def set_payload(self, payload):
        self.current_payload = payload

    def set_task(self, task):
        self.current_task = task

    def set_result(self, result):
        self.result = result

    def get_iteration(self):
        return self.current_iteration

    def get_parameter(self):
        return self.current_fuzzing_parameter

    def get_payload(self):
        return self.current_payload

    def get_task(self):
        return self.current_task

    def get_result(self):
        return self.result

BYTE = 8
WORD = 16
DWORD = 32
QWORD = 64

if __name__ == "__main__":
    print check_response("ERROR 503")