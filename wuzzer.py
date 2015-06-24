#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import socket
import os
from sys import stdout
from socket import error as socket_error
import multiprocessing
import argparse
import http
from iterator import Iterator
from case_config import REQUESTS
from caseLogger import *
from utils import *

# TODO: Add vectors for web apps testinx (xss etc)
# TODO: CLient Fuzzing


# TODO: Сделать генератор poc было бы хорошо. и тогда убрать этот дурацкий oneshot
# TODO: Отдельный режим ВСЕМ ПИЗДЕЦ - вместо meat - херачить с помощью радамсы и ззуфа

# TODO: Maybe to add time option (for example, enabling sleeping on errors etc) as a command line argument
# TODO: Add some parameters to generate POC (e.g. mode = poc, payload = payload_value, parameter = parameter_value)

DEFAULT_PORT = 80


class Logger(multiprocessing.Process):
    def __init__(self, result_queue, workers_count, output_file=None):
        multiprocessing.Process.__init__(self)
        self.result_queue = result_queue
        self.to_file = None
        self.output = None
        self.caseLoger = None
        self.completed_workers = 0
        self.workers_count = workers_count
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
        try:
            self.handle_task()
        except KeyboardInterrupt:
            pass

    def stop(self):
        print "[!]{}: Trying to save all ramained cases to db...".format(self.name)
        print "{} cases remains".format(self.result_queue.qsize())
        if self.result_queue.qsize() > 0:
            self.handle_task()
        try:
            self.terminate()
        except Exception, e:
            print e
            pass

    def handle_task(self):
            while True:
                task = self.result_queue.get()
                if task is None:
                    self.completed_workers +=1
                    if self.completed_workers == self.workers_count:
                        break
                else:
                    stdout.write("\r{} cases left to log\t\t\t\t".format(self.result_queue.qsize()))
                    stdout.flush()
                    if self.to_file is True:
                        self.caseLoger.write_case(task.get_iteration(), task.get_parameter(), task.get_payload(),
                                                  str(task.get_task()), str(task.get_result()),
                                                  check_response(task.get_result()))
            self.caseLoger.close_db()

class Sender(multiprocessing.Process):

    def __init__(self, task_queue, result_queue, host, delay):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.host = host
        self.delay = delay
        self.task = None

    def run(self):
        try:
            sleeping_time = 10
            sleeping_flag = False
            print "[!]{}: Starting".format(self.name)
            while True:
                if self.delay > 0:
                    time.sleep(self.delay)
                self.task = self.task_queue.get()
                if self.task is None:
                    break
                if sleeping_flag is not True:
                    res = self.send(self.task.get_task())
                if -1 == res:
                        sleeping_flag = True
                        sleeping_time += 10
                        print "Will wait for...{} seconds".format(sleeping_time)
                        time.sleep(sleeping_time)
                else:
                    sleeping_flag = False
                    sleeping_time = 10
                    print "Remained queue: {}".format(self.task_queue.qsize())
                    self.result_queue.put(self.task)
            self.result_queue.put(None)
            print "[!]{}:All tasks done".format(self.name)
        except KeyboardInterrupt:
            self.result_queue.put(self.task)
            pass

    def stop(self):
        try:
            self.terminate()
        except Exception, e:
            print e
            pass

    def send(self, task):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.connect(self.host)
        except socket_error as e:
            # TODO: REPEAT THE SAME TASK AFTER WAITING
            print "[-]Error connecting to host: {}".format(e)
            if e.errno == errno.ECONNREFUSED:
                return -1
            else:
                sys.exit(-1)
        try:
            sock.sendall(task)
            resp = sock.recv(1024).split("\r\n")[:1]
            sock.close()
            return self.task.set_result(resp)
        except Exception, e:
            print "[-]%s" % (str(e))
            sock.close()
            return self.task.set_result(e)


class Populator(multiprocessing.Process):

    def __init__(self, task_queue, host, proxy, modes, methods, ext_config, workers_count):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.methods = methods
        self.modes = modes
        self.ext_config = ext_config
        self.host = host
        self.proxy = proxy
        self.workers_count = workers_count

    def run(self):
        try:
            jobs = 0
            for method in self.methods:
                for mode in self.modes:
                    if self.ext_config:
                        raw_requests = REQUESTS
                        for raw in raw_requests:
                            iterator = Iterator(self.host, mode, method, raw, proxy)
                            """(self.current_payload, self.current_parameter, self.request.assemble_request())"""
                            for index, request in enumerate(iterator):
                                task = Task(index, request[1], request[0], request[2])
                                jobs += 1
                                self.task_queue.put(task)
                    else:
                        iterator = Iterator(self.host, mode, method, None, proxy)
                        """(self.current_payload, self.current_parameter, self.request.assemble_request())"""
                        for index, request in enumerate(iterator):
                            task = Task(index, request[1], request[0], request[2])
                            jobs += 1
                            self.task_queue.put(task)
            for _ in range(self.workers_count):
                self.task_queue.put(None)

        except KeyboardInterrupt:
            pass

    def stop(self):
        try:
            self.terminate()
        except Exception, e:
            print e


def main(threads, host, proxy, modes, methods, delay, ext_config, logfile):

    task_queue = multiprocessing.Queue()
    result_queue = multiprocessing.Queue()
    workers_count = threads
    if proxy:
        worker_host = proxy
    else:
        worker_host = host
    workers = [Sender(task_queue, result_queue, worker_host, delay) for _ in xrange(workers_count)]
    workers.append(Logger(result_queue, workers_count, logfile))
    workers.append(Populator(task_queue, host, proxy, modes, methods, ext_config, workers_count))
    workers.reverse()
    for worker in workers:
        worker.start()

    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print "[!]Keyboard interrupted"
        for w in workers:
            w.stop()
            w.join()
    for w in workers:
        w.stop()
        w.join()

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
