__author__ = 'aplastunov'
from httpRequest import *
from generators import *

class Iterator(object):

    def __init__(self, host, mode, method, raw_request=None, proxy=None):
        # For DEBUG PURPOSE:
        self.request = HTTPRequest(host, method, raw_request)
        if proxy is not None:
            self.request.add_host_to_url(host)
        self.req_generator = request_generator(self.request.assemble_request())
        self.mode = mode

        self.proxy = proxy
        """TASK DETAILS"""
        self.current_payload = None
        self.current_parameter = None
        """HEADER VARIABLES"""
        self.current_header = 0
        self.headers = self.request.get_headers()
        self.header = None
        self.head_string_generator = None
        self.head_basic_auth_generator = None
        self.head_int_generator = None
        self.head_range_generator = None
        self.head_basic_header_generator = None
        self.temp_header_value = self.request.get_header_value(0)
        self.to_next_header()
        self.url_path_generator = None
        self.param = None
        """POST PARAMETERS VARIABLES"""
        self.post_presence = False
        if self.request.get_post_parameters_count() != 0:
            self.current_post_parameter = 0
            self.post_parameter = None
            self.post_parameters = self.request.get_post_parameters()
            self.temp_post_parameter_value = self.request.get_post_parameter_value(0)
            self.post_string_generator = None
            self.post_int_generator = None
            self.post_blob_generator = None
            self.to_next_post_parameter()
            self.post_presence = True

        """URL VARIABLES"""
        #
        self.url_presence = False
        if self.request.get_url_parameters_count() != 0:
            self.current_url_parameter = 0
            self.url = self.request.get_url()
            self.temp_url_parameter_value = self.request.get_url_parameter_value(0)
            self.url_string_generator = None
            self.url_int_generator = None
            self.url_url_generator = None
            self.to_next_url_parameter()
            self.url_presence = True
        # TODO: move all type difinitions to util package
        super(Iterator, self).__init__()

    def __iter__(self):
        return self

    # Functions to iterate through path
    def to_next_url_parameter(self):
        self.url_string_generator = None
        self.url_int_generator = None
        self.url_url_generator = None
        self.param = self.url[self.current_url_parameter]
        self.temp_url_parameter_value = self.request.get_url_parameter_value(self.current_url_parameter)
        self.current_parameter = self.request.get_url_parameter_value(self.current_url_parameter)
        if "string" == self.request.get_url_parameter_type(self.current_url_parameter):
            self.url_string_generator = string_generator(self.request.get_url_parameter_value(self.current_url_parameter))
        if "integer" in self.request.get_url_parameter_type(self.current_url_parameter):
            self.url_int_generator = decimal_generator()
        if "path" in self.request.get_url_parameter_type(self.current_url_parameter):
            self.url_string_generator = string_generator(self.request.get_url_parameter_value(self.current_url_parameter))

    def fuzz_url(self):
        try:
            #if self.param.type == "path":
            #    raise StopIteration
            if self.url_string_generator is not None:
                value = self.url_string_generator.next()
            elif self.url_int_generator is not None:
                value = self.url_int_generator.next()
            else:
                raise StopIteration
            self.request.set_url_parameter(self.current_url_parameter, value)
            self.current_payload = value
        except StopIteration, e:
            print e
            self.request.set_url_parameter(self.current_url_parameter, self.temp_url_parameter_value)
            self.current_url_parameter += 1
            if self.current_url_parameter == self.request.get_url_parameters_count():
                raise StopIteration
            self.to_next_url_parameter()

    # Functions to iterate through headers
    def to_next_header(self):
        self.head_string_generator = None
        self.head_basic_auth_generator = None
        self.head_int_generator = None
        self.head_range_generator = None
        self.head_basic_header_generator = None
        self.header = self.headers[self.current_header]
        self.temp_header_value = self.request.get_header_value(self.current_header)
        if "string" == self.request.get_header_type(self.current_header):
            self.head_string_generator = string_generator(self.request.get_header_value(self.current_header))
        if "basic_auth" == self.request.get_header_type(self.current_header):
            self.head_basic_auth_generator = basic_auth_generator(self.request.get_header_value(self.current_header))
        if "integer" == self.request.get_header_type(self.current_header):
            self.head_int_generator = decimal_generator()
        if "range" == self.request.get_header_type(self.current_header):
            self.head_range_generator = range_generator()
        if "connection" == self.request.get_header_type(self.current_header):
            self.head_basic_header_generator = basic_header_generator("connection")
        if "acceptcharset" == self.request.get_header_type(self.current_header):
            self.head_basic_header_generator = basic_header_generator("acceptcharset")
        if "acceptlanguage" == self.request.get_header_type(self.current_header):
            self.head_basic_header_generator = basic_header_generator("acceptlanguage")
        if "accept" == self.request.get_header_type(self.current_header):
            self.head_basic_header_generator = basic_header_generator("accept")
        if "acceptencoding" == self.request.get_header_type(self.current_header):
            self.head_basic_header_generator = basic_header_generator("acceptencoding")
        if "contentType" == self.request.get_header_type(self.current_header):
            self.head_basic_header_generator = basic_header_generator("contenttype")

    def fuzz_headers(self):
        try:
            if self.header.fuzz is False:
                raise StopIteration
            if self.head_string_generator is not None:
                value = self.head_string_generator.next()
            elif self.head_basic_auth_generator is not None:
                value = self.head_basic_auth_generator.next()
            elif self.head_int_generator is not None:
                value = self.head_int_generator.next()
            elif self.head_range_generator is not None:
                value = self.head_range_generator.next()
            elif self.head_basic_header_generator is not None:
                value = self.head_basic_header_generator.next()
            else:
                raise StopIteration
            self.request.set_header(self.current_header, value)
            self.current_payload = value
            self.current_parameter = self.request.get_header_name(self.current_header)

        except StopIteration, e:
            print e
            self.request.set_header(self.current_header, self.temp_header_value)
            self.current_header += 1
            if self.current_header == self.request.get_headers_count():
                raise StopIteration
            self.to_next_header()

    # Functions to iterate through post parameters
    def to_next_post_parameter(self):
        self.post_string_generator = None
        self.post_int_generator = None
        self.post_parameter = self.post_parameters[self.current_post_parameter]
        self.temp_post_parameter_value = self.request.get_post_parameter_value(self.current_post_parameter)
        if "string" == self.request.get_post_parameter_type(self.current_post_parameter):
            self.post_string_generator = string_generator(self.request.get_post_parameter_value(self.current_post_parameter))
        if "integer" in self.request.get_post_parameter_type(self.current_post_parameter):
            self.post_int_generator = decimal_generator()
        if "blob" in self.request.get_post_parameter_type(self.current_post_parameter):
            self.post_blob_generator = blob_generator(self.request.get_post_parameter_value(self.current_post_parameter))
        if "xml" == self.request.get_post_parameter_type(self.current_post_parameter):
            self.post_string_generator = string_generator(self.request.get_post_parameter_value(self.current_post_parameter))

    def fuzz_post_data(self):
        try:
            if self.post_string_generator is not None:
                value = self.post_string_generator.next()
            elif self.post_int_generator is not None:
                value = self.post_int_generator.next()
            elif self.post_blob_generator is not None:
                value = self.post_blob_generator.next()
            else:
                raise StopIteration
            self.current_parameter = self.request.get_post_parameter_name(self.current_post_parameter)
            self.request.set_post_parameter(self.current_post_parameter, value)
            self.current_payload = value
        except StopIteration, e:
            print e
            self.request.set_post_parameter(self.current_post_parameter, self.temp_post_parameter_value)
            self.current_post_parameter += 1
            if self.current_post_parameter == self.request.get_post_parameters_count():
                raise StopIteration
            self.to_next_post_parameter()

    def fuzz_whole_request(self):
        req = self.req_generator.next()
        self.current_payload = req
        self.current_parameter = "WHOLE REQUEST"

    def next(self):
        # FUZZMODE = "url-data"
        if (FUZZMODES[2] == self.mode) & (self.url_presence is True):
            self.fuzz_url()
        # FUZZMODE = "headers"
        if FUZZMODES[0] == self.mode:
            self.fuzz_headers()
        # FUZZMODE == "post-data"
        if (FUZZMODES[1] == self.mode) & (self.post_presence is True):
            self.fuzz_post_data()
        if FUZZMODES[3] == self.mode:
            self.fuzz_whole_request()
            return self.current_payload, self.current_parameter, self.current_payload
        return self.current_payload, self.current_parameter, self.request.assemble_request()

