#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = '@aplastunov'

from utils import *
from namedlist import namedlist

"""FIRST LINE OF HTTP REQUEST"""
FIRSTLINER = namedlist("FIRSTLINER", "method url version")
"""TASK format"""

class HttpParser:

    def __init__(self, request=None):
        self.request = request
        if self.request is not None:
            self.parse_request()
        else:
            self.method, self.url_data, self.version = None
            self.headers = None
            self.post_data = None
            self.host = None

    def parse_request(self):
        self.method, self.url_data, self.version = self.parse_first_line(self.request)
        self.headers = self.parse_headers(self.request)
        self.post_data = self.parse_data(self.request)
        self.host = self.parse_host(self.request)

    def parse_first_line(self, request=None):
        first_line = request.split("\r\n")[0]
        url_data = []
        # ToDo: regex to check if first line is valid
        try:
            method, url, version = first_line.split(" ")
            version = version.split("/")[1]
        except (IndexError, ValueError):
            raise ValueError("InvalidRequest")
        path, parameters = url.split("?")
        for directory in path.split("/")[1:]:
            # PATH = namedlist("PATH", "type delimiter name value content")
            url_data.append(PATH(type="path", delimiter=None, name="", value=directory, content="path"))
        for pair in parameters.split("&"):
            parameter = pair.split("=")
            if len(parameter) != 2:
                raise ValueError("InvalidRequest")
            if is_float(parameter[1]) is True:
                act_content = "integer"
            else:
                act_content = "string"
            # PATH = namedlist("PATH", "type delimiter name value content")
            url_data.append(PATH(type=act_content, name=parameter[0], delimiter="=", value=parameter[1], content=act_content))
        return method, url_data, version

    def parse_headers(self, request):
        headers = []
        for line in request.split("\r\n")[1:]:
            if line == "":
                break
            # ToDo add regex to exclude first line from headers (for now, it all starts from second line)
            '''
            if regex(line):
                continue # Skipping firstline
            '''
            delim_pos = line.find(":")
            header = (line[0:delim_pos], line[delim_pos+1:].strip())
            if len(header) < 2:
                raise ValueError("InvalidRequest")
            if is_float(header[1]) is True:
                act_content = "integer"
            elif header[0] in HEADER_GEN_MAP.keys():
                act_content = HEADER_GEN_MAP.get(header[0])
                pass
            else:
                act_content = "string"
            # HEADER = namedlist("HEADER", "name delimiter value content default fuzz")
            headers.append(HEADER(name=header[0], delimiter=":", value=header[1], content=act_content, default=header[1], fuzz=True))
        return headers

    def parse_data(self, request):
        data = []
        req_tmp = request.split("\r\n")
        pos = req_tmp.index("")
        # ToDo: For now parses only x-www-form-urlencoded i.e. simplest post data
        if pos is not None:
            for pair in req_tmp[pos+1].split("&"):
                parameter = pair.split("=")
                if len(parameter) != 2:
                    raise ValueError("InvalidRequest")
                if is_float(parameter[1]) is True:
                    act_content = "integer"
                else:
                    act_content = "string"
                # DATA = namedlist("DATA", "name delimiter value content")
                data.append(DATA(name=parameter[0], delimiter="=", value=parameter[1], content=act_content))

        # ToDo: Here to add parsing of multipart/ post data
        return data

    def parse_host(self, request):
        for line in request.split("\r\n")[1:]:
            delim_pos = line.find(":")
            header = (line[0:delim_pos], line[delim_pos+1:].strip())
            if "HOST".lower() in header[0].lower():
                host = header[1].split(":")
                if len(host) < 2:
                    host.extend([80])
                else:
                    host[1] = int(host[1])
                break

        return host[0], host[1]

    def get_first_line(self):
        return self.method, self.url_data, self.version

    def get_headers(self):
        return self.headers

    def get_data(self):
        return self.post_data

    def get_host(self):
        return self.host

if __name__ == "__main__":

    test_request = '\r\n'.join(["POST /admin/createProject.html?param1=why&param2=so&param3=serious&test=123 HTTP/1.1",
                               "Host: 172.16.2.107",
                               "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:37.0) Gecko/20100101 Firefox/37.0",
                               "Accept: text/javascript, text/html, application/xml, text/xml, */*",
                               "Accept-Language: en-US,en;q=0.5",
                               "Accept-Encoding: gzip, deflate",
                               "X-Requested-With: XMLHttpRequest",
                               "X-Prototype-Version: 1.7.2",
                               "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
                               "Referer: http://172.16.2.107:8111/admin/createProject.html?cameFromUrl=%2Fadmin%2Fadmin.html%3Fitem%3Dprojects",
                               "Content-Length: 221",
                               "Cookie: TCSESSIONID=D77CBCBC2D677102B2CB3F1A5DC4E10D; __test=1;",
                               "DNT: 1",
                               "Connection: keep-alive",
                               "Pragma: no-cache",
                               "Cache-Control: no-cache",
                               "",
                               "param1=hello&param2=world&test=azaza"])

    parser = HttpParser(test_request)
    parser.parse_request()