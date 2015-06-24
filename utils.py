"""Utility module with types difinitions"""
from namedlist import namedlist
import sys


FUZZMODES = ["headers", "post-data", "url-data", "whole-request", "poc"]
HTTP_METHODS = ["HEAD", "GET", "POST", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT"]
INPUT = ["wuzzer", "custom", "pcap"]

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

BYTE = 8
WORD = 16
DWORD = 32
QWORD = 64
VALID_PROMPTS = {'yes': True, 'y': True, 'no': False, 'n': False}


def question(msg):
    while True:
        choice = raw_input('[>] {} y/n\r\n'.format(msg)).lower()
        if choice in VALID_PROMPTS:
            return VALID_PROMPTS[choice]
        else:
            print("[!] Please type Y or N")


if __name__ == "__main__":
    a = question("test?")
    print (a)