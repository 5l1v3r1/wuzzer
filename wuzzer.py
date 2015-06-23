#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import socket
import os
import sys
from socket import error as socket_error
import multiprocessing
import argparse
import http
from httpRequest import *
from generators import *
from case_config import REQUESTS
from caseLogger import *


# TODO: Add vectors for web apps testinx (xss etc)
# TODO: CLient Fuzzing


# TODO: Сделать генератор poc было бы хорошо. и тогда убрать этот дурацкий oneshot
# TODO: Отдельный режим ВСЕМ ПИЗДЕЦ - вместо meat - херачить с помощью радамсы и ззуфа

# TODO: Maybe to add time option (for example, enabling sleeping on errors etc) as a command line argument
# TODO: Add some parameters to generate POC (e.g. mode = poc, payload = payload_value, parameter = parameter_value)
HTTP_METHODS = ["HEAD", "GET", "POST", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT"]
FUZZMODES = ["headers", "post-data", "url-data", "whole-request", "poc"]
INPUT = ["wuzzer", "custom", "pcap"]
DEFAULT_PORT = 80


class Logger(multiprocessing.Process):
    def __init__(self, result_queue, output_file=None, verbosity=None):
        multiprocessing.Process.__init__(self)
        self.result_queue = result_queue
        self.to_file = None
        self.output = None
        self.caseLoger = None
        self.verbosity = verbosity
        if output_file is None:
            self.to_file = False
        else:
            self.to_file = True
            try:
                if os.path.isfile(output_file):
                    os.remove(output_file)
                self.caseLoger = CaseLogger(db_name=output_file)
                self.caseLoger.prepare_db()
            except IOError, e:
                print "[-] Cannot create log file:{}".format(e)
                self.to_file = False

    def run(self):
        while True:
            task = self.result_queue.get()
            if task is None:
                self.output.close()
                break
            #print "[!]Iteration {}".format(task.get_iteration())
            #print "Current parameter: {}".format(task.get_parameter())
            #print "Payload: {}".format(task.get_payload())
            #print "Result: {}\r\n\r\n".format(task.get_result())
            if self.to_file is True:
                self.caseLoger.write_case(task.get_iteration(), task.get_parameter(), task.get_payload(),
                                          str(task.get_task()), str(task.get_result()),
                                          check_response(task.get_result()))

    def stop(self):
        try:
            self.result_queue.task_done()
            self.output_all.close()
            self.output_err.close()
            self.terminate()
        except Exception, e:
            print e
            pass


class Sender(multiprocessing.Process):

    def __init__(self, task_queue, result_queue, host, delay):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.host = host
        self.delay = delay
        self.task = None

    def run(self):
        sleeping_time = 10
        sleeping_flag = False
        print "[!]{}: Starting".format(self.name)
        while True:
            if self.delay > 0:
                time.sleep(self.delay)
            self.task = self.task_queue.get()
            #print self.task.get_task()
            if self.task.get_task() is None:
                print "[!]{}: Exiting".format(self.name)
                break
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.connect(self.host)
            except socket_error as e:
                # TODO: REPEAT THE SAME TASK AFTER WAITING
                print "[-]Error connecting to host: {}".format(e)
                if e.errno == errno.ECONNREFUSED:
                    if sleeping_flag is True:
                        sleeping_time += 10
                    print "Will wait for...{} seconds".format(sleeping_time)
                    time.sleep(sleeping_time)
                    continue
                else:
                    sys.exit(-1)
            try:
                sleeping_flag = False
                sleeping_time = 10
                sock.sendall(self.task.get_task())
                resp = sock.recv(1024).split("\r\n")[:1]
                self.task.set_result(resp)
            except Exception, e:
                print "[-]%s" % (str(e))
                self.task.set_result(e)
            sock.close()
            self.task_queue.task_done()
            print "Remained queue: {}".format(self.task_queue.qsize())
            self.result_queue.put(self.task)

    def stop(self):
        try:
            self.task_queue.task_done()
            self.terminate()
        except Exception, e:
            print e
            pass


class Receiver(multiprocessing.Process):

    def __init__(self, task_queue,result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        pass


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
            return (self.current_payload, self.current_parameter, self.current_payload)
        return (self.current_payload, self.current_parameter, self.request.assemble_request())


def main(threads, host, proxy, modes, methods, delay, ext_config, logfile):

    task_queue = multiprocessing.JoinableQueue()
    result_queue = multiprocessing.Queue()
    workers_count = threads
    if proxy:
        workers = [Sender(task_queue, result_queue, proxy, delay) for w in xrange(workers_count)]
    else:
        workers = [Sender(task_queue, result_queue, host, delay) for w in xrange(workers_count)]
    logger = Logger(result_queue, logfile)
    try:
        for w in workers:
            w.start()
        logger.start()
        jobs = 0
        for method in methods:
            for mode in modes:
                if ext_config:
                    raw_requests = REQUESTS
                    for raw in raw_requests:
                        iterator = Iterator(host, mode, method, raw, proxy)
                        """(self.current_payload, self.current_parameter, self.request.assemble_request())"""
                        for index, request in enumerate(iterator):
                            task = Task(index, request[1], request[0], request[2])
                            jobs += 1
                            task_queue.put(task)
                else:
                    iterator = Iterator(host, mode, method, None, proxy)
                    """(self.current_payload, self.current_parameter, self.request.assemble_request())"""
                    for index, request in enumerate(iterator):
                        task = Task(index, request[1], request[0], request[2])
                        jobs += 1
                        task_queue.put(task)

        for i in xrange(workers_count):
            task_queue.put(None)
        task_queue.join()
        result_queue.put(None)
        result_queue.join()
    except KeyboardInterrupt:
        print "[!]Keyboard interrupted"
        for w in workers:
            w.stop()
            # Сruthes. Need to empty Queue first
            w.join()
        logger.stop()
        logger.join()
        exit(0)
    for w in workers:
        w.stop()
        w.join()
    logger.stop()
    logger.join()
    exit(0)

if __name__ == "__main__":
    proxy = None
    modes = None
    methods = None
    target = None
    url_parameters = None
    logfile = None

    THREADS_HELP = "Number of threads for sending requests"
    PROXY_HELP = "Proxy\'s host:port, if required. Example:127.0.0.1:8080"
    MODE_HELP = "Fuzzing modes. By default \'headers\' only will be fuzzed"
    METHOD_HELP = "HTTP methods to test. (default: all available methods"
    INPUT_HELP = "Source of http request to fuzz"
    TARGET_HELP = "Target\'s host:port (default port: 80). Example: www.google.com:80\n"
    DELAY_HELP = "Delay between request. In seconds\n"
    CONFIG_HELP = "Using of external config file for specifying fuzzing requests. By dafault = False\n"
    OUTPUT_HELP = "SQLite db file to write fuzzing results\n"
    parser = argparse.ArgumentParser(description="Wuzzer: The Dumbest HTTP fuzzer")
    parser.add_argument("--threads", type=int, help=THREADS_HELP)
    parser.add_argument("--proxy", help=PROXY_HELP)
    parser.add_argument("--mode", nargs="+", default=[FUZZMODES[0]], choices=FUZZMODES, help=MODE_HELP)
    parser.add_argument("--method", nargs="+", default=HTTP_METHODS, choices=HTTP_METHODS, help=METHOD_HELP)
    parser.add_argument("--input", default=INPUT[0], choices=INPUT, help=INPUT_HELP)
    parser.add_argument("--target", required=True, help=TARGET_HELP)
    parser.add_argument("--delay", type=float, default=0, help=DELAY_HELP)
    parser.add_argument("--config", type=bool, default=False, help=CONFIG_HELP)
    parser.add_argument("--output", help=OUTPUT_HELP)

    args = parser.parse_args()
    # Parse fuzzing mode
    modes = args.mode
    methods = args.method
    delay = args.delay
    ext_config = args.config
    # Parse & Check target host
    target = args.target.split(":")
    if len(target) < 2:
        target.append(str(DEFAULT_PORT))
    try:
        int(target[1])
    except ValueError:
        print "[-]Incorrect Target: {}".format(":".join(target))
        sys.exit(-1)
    if not (http._is_valid_port(int(target[1]))	):
        print "[-]Incorrect Target: {}".format(":".join(target))
        sys.exit(-1)
    if not (http._is_valid_host(target[0])):
        print "[-]Incorrect Target: {}".format(":".join(target))
        sys.exit(-1)
    if args.threads is not None:
        threads = args.threads
    else:
        threads = multiprocessing.cpu_count() * 2
    # Parse & Check proxy host
    print "[!]Wuzzer\'s Options:"
    if args.proxy:
        proxy = args.proxy.split(":")
        if len(proxy) <2:
            print "[-]Incorrect Proxy"
            sys.exit(-1)
        try:
            int(proxy[1])
        except ValueError:
            print "[-]Incorrect Proxy: {}".format(":".join(proxy))
            sys.exit(-1)
        print "\t\t[+]Proxy: {} {}".format(proxy[0], proxy[1])
    else:
        print "\t\t[+]Proxy: None"
    print "\t[!]Number of threads =  {}".format(threads)
    print "\t[!]Networks\'s Options:"
    print "\t\t[+]Target: {} {}".format(target[0],target[1])
    host = (target[0], int(target[1]))

    if proxy is not None:
        proxy_host = (proxy[0], int(proxy[1]))
        print "\t[+]Proxy: %s:%d" % proxy_host
    else:
        proxy_host = None
        print "\t[+]Proxy: None"
    print "\t[!]Fuzzing Options:"
    print "\t\t[+]Mode: {}".format(", ".join(m for m in modes))
    print "\t\t[+]Methods to test: {}".format(", ".join(m for m in methods))
    if args.output is not None:
        logfile = args.output
        if os.path.isfile(logfile) is True:
            answer = question("{} file already exists. Overwrite?".format(logfile))
            if answer is False:
                print "[!] DB file will not be overwritten. Exiting"
                sys.exit(-1)
    main(threads, host, proxy_host, modes, methods, delay, ext_config, logfile)
