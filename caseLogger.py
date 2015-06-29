import sqlite3
import errno
from datetime import datetime

http_err = "HTTP_ERR"
socket_err = "SOCKET_ERR"
timeout_err = "TIMEOUT_ERR"
def check_response(message):
    if "502" in message or "503" in message:
        return http_err
    elif "timed out" in message:
        return timeout_err
    elif isinstance(message, Exception):
        if (message.errno == errno.ECONNREFUSED) \
                or (message.errno == errno.ECONNABORTED) \
                or (message.errno == errno.ECONNRESET) \
                or (message.errno == errno.ENETRESET):
            return socket_err
        else:
            return message.errno
    else:
        return "OK"

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


class CaseLogger:
    TABLE_NAME = "wuzzer_log"
    db_name = "wuzz.db"
    iteration = None
    cur = None
    conn = None

    def __init__(self, db_name=None):
        if db_name is not None:
            self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.conn.text_factory = str
        self.cur = self.conn.cursor()

    def prepare_db(self):
            self.cur.execute("CREATE TABLE IF NOT EXISTS {} (iteration INTEGER, time integer,"
                             " parameter TEXT, payload BLOB, request BLOB, response TEXT, result TEXT)".format(self.TABLE_NAME))
            self.conn.commit()

    def get_last_iter(self):
        query = "SELECT COUNT(*) from {}".format(self.TABLE_NAME)
        self.cur.execute(query)
        return self.cur.fetchone()[0]

    def read_case_by_iter(self, iteration=None):
        if iteration is not None:
            query = "SELECT * from {} WHERE iteration=?".format(self.TABLE_NAME)
            self.cur.execute(query, (iteration,))
            result = self.cur.fetchone()
        else:
            query = "SELECT * from {}".format(self.TABLE_NAME)
            self.cur.execute(query)
            result = self.cur.fetchmany(10)
        return result

    def get_error_case(self):
        query = "SELECT * from {} WHERE result like '%ERR%' ORDER BY time limit 1".format(self.TABLE_NAME)
        self.cur.execute(query)
        return self.cur.fetchone()

    def write_case(self, iteration, parameter, payload, request, response, result):
        now = datetime.now()
        # stamp = mktime(now.timetuple())
        query = "INSERT INTO {} VALUES (?,?,?,?,?,?,?)".format(self.TABLE_NAME)
        if result is None:
            result = "NO RESULT"
        else:
            result = str(result).upper()
        try:
            self.cur.execute(query, (iteration, now, parameter, str(payload), request, response, result))
            self.conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError("DuplicateIteration")
        return 0

    def close_db(self):
        self.conn.commit()
        self.conn.close()


if __name__ == '__main__':
    log = CaseLogger("test.db")
    log.prepare_db()
    req = ''.join(("GET / HTTP/1.1\r\n",
                   "Accept-Charset: utf-8\r\n",
                   "Connection: Keep-Alive\r\n",
                   "Accept-Language: en-US,ru-RU\r\n",
                   "Accept-Encoding: gzip, bzip2, gzip, deflate, exi, identity, lzma,Pragma: no-cache\r\n",
                   "Cache-Control: , s-maxage=1062309894735254426, no-store\r\n",
                   "Referer: 218.47.163.225\r\n",
                   "Host: 127.0.0.1:80\r\n",
                   "Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, */*\r\n",
                   "User-Agent: Mozilla/5.0 (Linux; U; Android 4.1.1; en-gb; Nexus 7 Build/JRO03D) AFL/01.04.02\r\n",
                   "\r\n"))

    print log.get_last_iter()
    log.write_case(log.get_last_iter()+1, "ACCEPT-CHARSET", "utf-8", req, "200", "oERRor")

    print log.read_case_by_iter(1)
    print "\r\n\r\n"
    print log.read_case_by_iter()
    print "\r\n\r\nERRORS:"
    print log.get_error_case()
