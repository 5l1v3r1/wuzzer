# -*- coding: utf-8 -*-
__author__ = '@aplastunov'

from utils import HEADER, PATH, DATA
from case_config import REQUESTS
from HttpParser import HttpParser
from namedlist import namedlist
# TODO: Add WebDAV support


# TODO: ADD ZZUF MUTATIONS TO EACH TYPES OF GENERATORS
# TODO: ADD posibility to generate large number of folders and GET-parameters in url
# TODO: ADD XML/SOAP/JSON/... GENERATOR
# TODO: Add support of multiple different request
# TODO: Add state-based fuzzing (e.g. sending one request only after sending another) - just like sulley
# TODO: Add Cookie parser
# TODO: Add plaintext request parser & converter to httpReqest format

DELIMITER = "\r\n"
HEADER_DELIMITER = ":"
PATH_DELIMITER = "/"
PARAMETER_DELIMITER = "="
PATH_PARAMETER_DELIMITER = "?"
PARAMETER_SEPARATOR_DELIMITER = "&"


class HTTPRequest():

    def __init__(self, host, method="GET", raw_request=None):
        self.method = method
        self.host = host
        self.version = "1.1"
        self.url = None
        self.post_data = None
        self.headers = None
        self.length = 0
        if raw_request is None:
            self.use_default_config()
        else:
            self.use_external_config(raw_request)
        if self.method == "POST":
            for d in self.post_data:
                self.length += len(d.name) + len(str(d.value))

    def use_default_config(self):
        self.url = [
           #PATH(type="path", name="loginurl", delimiter=None, value="/", content="string"),
           #PATH(type="path", name="", delimiter=None, value="UsageTypesInfo", content="string"),
        ]
        self.post_data = [
            DATA(name="test", delimiter="=", value="test_val", content="string"),
            DATA(name="test2", delimiter="=", value="test2_val", content="string"),
        ]

        self.headers = [
            # TODO: Add Default Value. If Default Value is None - skip header during fuzz of other headers
            HEADER(name="Connection", delimiter=":", value="Keep-Alive", content="connection", default="Keep-Alive",
                   fuzz=True),
            HEADER(name="Accept-Charset", delimiter=":", value="utf-8", content="acceptcharset", default="utf-8",
                   fuzz=True),
            HEADER(name="Accept-Language", delimiter=":", value="en-US,ru-RU", content="acceptlanguage",
                   default="en-US,ru-RU", fuzz=True),
            HEADER(name="Cache-Control", delimiter=":", value="s-maxage=1062309894735254426, no-store",
                   content="string", default="s-maxage=1062309894735254426, no-store", fuzz=True),
            HEADER(name="Referer", delimiter=":", value="%s:%d" % self.host, content="string",
                   default="%s:%d" % self.host, fuzz=True),
            HEADER(name="Accept", delimiter=":", value="*/*", content="accept", default="*/*", fuzz=True),
            HEADER(name="Accept-Encoding", delimiter=":", value="", content="acceptencoding", default="", fuzz=True),
            HEADER(name="Content-Length", delimiter=":", value=self.length, content="integer", default=self.length, fuzz=True),
            HEADER(name="Content-Type", delimiter=":", value="*", content="contenttype", default=None, fuzz=True),
            HEADER(name="Host", delimiter=":", value="%s:%d" % self.host, content="string", default="%s:%d" % self.host,
                   fuzz=True),
            HEADER(name="Cookie", delimiter=":", value="JSESSION=D77CBCBC2D677102B2CB3F1A5DC4E10D; secret_cookie=1;", content="cookie", default="",
                   fuzz=True),
            HEADER(name="User-Agent", delimiter=":", value="WebInterface", content="string", default="WebInterface",
                   fuzz=True),
            HEADER(name="Range", delimiter=":", value="bytes=0-1000", content="range", default=None, fuzz=True),
            HEADER(name="Authorization", delimiter=":", value="Basic {}".format("user:public".encode('base64')[:-1]),
                   content="basic_auth", default=None, fuzz=True)
            ]

    def use_external_config(self, request):
        try:
            parser = HttpParser(request)
            self.method, self.url, self.version = parser.get_first_line()
            self.headers = parser.get_headers()
            self.post_data = parser.get_data()
            self.host = parser.get_host()

        except Exception, e:
            print "Bad config file: {}\nDefault settings will be used".format(e)
            self.use_default_config()

    def get_headers(self):
        return self.headers

    def get_headers_count(self):
        return len(self.headers)

    def get_header_type(self, number):
        if number < 0:
            return None
        return self.headers[number].content

    def get_header_name(self, number):
        if number < 0:
            return None
        return self.headers[number].name

    def get_header_value(self, number):
        if number < 0:
            return None
        return self.headers[number].value

    def get_post_parameters(self):
        if len(self.post_data) > 0:
            return self.post_data
        else:
            return []

    def get_post_parameters_count(self):
        return len(self.post_data)

    def get_post_parameter_type(self, number):
        if number < 0:
            return None
        return self.post_data[number].content

    def get_post_parameter_name(self, number):
        if number < 0:
            return None
        return self.post_data[number].name

    def get_post_parameter_value(self, number):
        if number < 0:
            return None
        return self.post_data[number].value

    def get_url(self):
        return self.url

    def get_url_parameters_count(self):
        return len(self.url)

    def get_url_parameter_type(self, number):
        if number < 0:
            return None
        return self.url[number].content

    def get_url_parameter_name(self, number):
        if number < 0:
            return None
        return self.url[number].name

    def get_url_parameter_value(self, number):
        if number < 0:
            return None
        return self.url[number].value

    def set_method(self, method):
        self.method = method

    # def set_url_path(self, path):
    # self.url_path = path

    def set_header(self, number, value):
        self.headers[number].value = value

    def set_post_parameter(self, number, value):
        self.post_data[number].value = value

    def set_url_parameter(self, number, value):
        self.url[number].value = value

    def add_host_to_url(self, host):
        url = self.get_url()
        url.insert(0, PATH(type="host", delimiter=None, name="", value="http://{}:{}".format(host[0],host[1]), content="path"))

    def assemble_request(self):

        path = self.assemble_url()
        firstline = "{} {} HTTP/{}\r\n".format(self.method, path, self.version)
        if self.method == "POST":
            post_parameters = self.assemble_post()
        else:
            post_parameters = DELIMITER
        headers = DELIMITER.join("{}{} {}".format(header.name, header.delimiter, header.value) for header in self.headers)
        req = firstline + headers + DELIMITER + post_parameters
        return req

    def assemble_url(self):
        path = ""
        check_path = True
        if len(self.url) == 0:
            path = PATH_DELIMITER
        else:
            for u in self.url:
                if ("host" == u.type) & (check_path is True):
                    path += str(u.value)
                if ("path" == u.type) & (check_path is True):
                    path += PATH_DELIMITER + str(u.value)
                if ("path" != u.type) & (check_path is True):
                    path += PATH_PARAMETER_DELIMITER+u.name+PARAMETER_DELIMITER+ str(u.value)
                    check_path = False
                elif check_path is False:
                    path += PARAMETER_SEPARATOR_DELIMITER+u.name+PARAMETER_DELIMITER+str(u.value)
        return path

    def assemble_post(self):
        if (len(self.post_data) == 0):
            return DELIMITER
        if (len(self.post_data) == 1) & (self.post_data[0].content == "blob"):
            post_parameters = DELIMITER + self.post_data[0].value + DELIMITER
        elif (len(self.post_data) == 1) & (self.post_data[0].content == "xml"):
            post_parameters = DELIMITER + self.post_data[0].value + DELIMITER
        else:
            post_parameters = DELIMITER
            post_parameters += "&".join("{}{}{}".format(post_data.name, post_data.delimiter, post_data.value) for post_data in self.post_data)
            post_parameters += DELIMITER
        return post_parameters

if __name__ == "__main__":
    for raw_request in REQUESTS:
        request = HTTPRequest(("127.0.0.1", 47989), method="GET", raw_request=raw_request)
        print request.assemble_request()