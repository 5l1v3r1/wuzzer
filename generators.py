# -*- coding: utf-8 -*-
import random
import re
from utils import *
from pyZZUF import *

# TODO: ADD METHOD FUZZING
MIMETYPES = ["text/html", "example", "*/*"
                                     "image/gif", "image/jpeg", "image/pjpeg", "image/png", "image/svg+xml", "image/vnd.djvu", "image/example",
             "message/http", "message/imdn+xml", "message/partial", "message/rfc822",
             "message/example",
             "multipart/mixed", "multipart/alternative", "multipart/related", "multipart/form-data", "multipart/signed", "multipart/encrypted", "multipart/example",
             "text/cmd", "text/css", "text/csv", "text/example", "text/javascript", "text/plain", "text/rtf", "text/vcard", "text/xml",
             "application/x-7z-compressed", "application/x-chrome-extension", "application/x-dvi", "application/x-font-ttf", "application/x-javascript", "application/x-latex", "application/x-mpegURL", "application/x-rar-compressed", "application/x-shockwave-flash", "application/x-tar", "application/x-www-form-urlencoded", "application/x-xpinstall", "text/x-jquery-tmpl", "application/x-pkcs12"]
ENCODINGS = ["compress", "deflate", "exi", "gzip", "identity", "pack200_gzip", "bzip2", "lzma", "peerdist", "sdch", "xz"]

CHARSETS = ["ascii", "ansi", "iso-8859-1", "utf-8", "utf-16", "windows-1251", "windows-1252"]

LANGUAGES = ["en-US", "ru-RU", "de-DE"]

CONNECTIONS = ["Keep-Alive", "Closed", "Upgrade"]

''' hell of a generator. Don't know how to create it properly =(
def cacheControl_generator():
	visibility = ['','private','public']
	caching = ['no-chache','no-store','no-transform','must-revalidate','proxy-revalidate']	
	age = 100
	sage = 100

	for v in visibility:
		visibility_generator = string_generator(v)
		for c in caching:
			v_val = visibility_generator.next()
			age_generator = int_generator()
			sage_generator = int_generator()
			caching_generator = string_generator(c)
			while True:
				try:
					c_val = caching_generator.next()
					yield visibility_generator.next()
				except StopIteration:
					break
			caching_generator = string_generator(c)
			while True:
				try:
					c_val = caching_generator.next()
					yield visibility_generator.next()
				except StopIteration:
					break					
	

	age = 'max-age=%d'%(random.randint(0,MAX_INT))
	sage = 's-maxage=%d'%(random.randint(0,MAX_INT))

	res = "%s, "%visibility[random.randint(0,len(visibility)-1)]
	if random.randint(0,1) == 1:
		res += "%s, "%age
	if random.randint(0,1) == 1:
		res += "%s, "%sage
	res += caching[random.randint(0,len(caching)-1)]
	#return res
'''
# TODO: Not only different dictionaries for different headers,
# TODO: but also separate sets of bad chars for them also. As soon as possible


def basic_header_generator(name):
    if name == "connection":
        dictionary = CONNECTIONS
    if name == "acceptcharset":
        dictionary = CHARSETS
    if name == "acceptlanguage":
        dictionary = LANGUAGES
    if name == "accept":
        dictionary = MIMETYPES
    if name == "acceptencoding":
        dictionary = ENCODINGS
    if name == "contentType":
        dictionary = MIMETYPES
    basic_value = dictionary[random.randint(0,len(dictionary)-1)]
    for step in [1, 10, 100 , 1000, 10000]:
        basic_value += ", ".format(dictionary[random.randint(0,len(dictionary)-1)])
        yield basic_value * step
    basic_value = dictionary[random.randint(0,len(dictionary)-1)]
    basic_gen = string_generator(basic_value)
    while True:
        try:
            yield basic_gen.next()
        except StopIteration:
            break

def request_generator(request):
    delimiters = ["\r\n", ":", "/", "\?", "=", "&", ",", ";"]
    temp = request.replace(delimiters[0], "")
    yield temp
    for delimiter in delimiters:
        delim_gen = delimiter_generator(delimiter)
        for pos in re.finditer(delimiter, request):
            while True:
                try:
                    replacement = delim_gen.next()
                    yield request[:pos.start()] + replacement + request[pos.start()+len(delimiter):]
                except StopIteration:
                    break
    prev_pos = 0
    for pos in re.finditer(delimiters[0], request):
        cur_pos = pos.start()
        replacement = request[prev_pos:cur_pos]
        yield request[:pos.start()] + replacement*2 + request[pos.start()+len(delimiter):]
        yield request[:pos.start()] + replacement*10 + request[pos.start()+len(delimiter):]
        yield request[:pos.start()] + replacement*100 + request[pos.start()+len(delimiter):]
        prev_pos = cur_pos
    replacement = request[prev_pos:]
    yield request[:pos.start()] + replacement*2 + request[pos.start()+len(delimiter):]
    yield request[:pos.start()] + replacement*10 + request[pos.start()+len(delimiter):]
    yield request[:pos.start()] + replacement*100 + request[pos.start()+len(delimiter):]
"""Uncompromisingly stolen from sulley (https://github.com/OpenRCE/sulley/)"""


def delimiter_generator(value="\r\n"):
    if value is None:
        raise StopIteration
    yield ""
    yield(value * 2)
    yield(value * 5)
    yield(value * 10)
    yield(value * 25)
    yield(value * 100)
    yield(value * 500)
    yield(value * 1000)

    if value == " ":
        yield("\t")
        yield("\t"*2)
        yield()

    yield(" ")
    yield("\t")
    yield("\t " * 100)
    yield("\t\r\n" * 100)
    yield("!")
    yield("@")
    yield("#")
    yield("$")
    yield("%")
    yield("^")
    yield("&")
    yield("*")
    yield("(")
    yield(")")
    yield("-")
    yield("_")
    yield("+")
    yield("=")
    yield(":")
    yield(": " * 100)
    yield(":7" * 100)
    yield(";")
    yield("'")
    yield("\"")
    yield("/")
    yield("\\")
    yield("?")
    yield("<")
    yield(">")
    yield(".")
    yield(",")
    yield("\r")
    yield("\n")
    yield("\r\n" * 64)
    yield("\r\n" * 128)
    yield("\r\n" * 512)


"""Most functionality were stolen from sulley fuzzing framework"""


def string_generator(value):
    yield value
    yield value * 2
    yield value * 10
    yield value * 100
    yield value * 1000
    yield value * 10000
    yield value * 100000



    yield value + "\xfe"
    yield value * 2 + "\xfe"
    yield value * 10 + "\xfe"
    yield value * 100 + "\xfe"
    yield value * 1000 + "\xfe"
    yield value * 10000 + "\xfe"
    yield value * 100000 + "\xfe"


    bad_strings = [
        # omission.
        "",
        # strings ripped from spike (and some others I added)
        "/.:/" + "A"*5000 + "\x00\x00",
        "/.../" + "A"*5000 + "\x00\x00",
        "/.../.../.../.../.../.../.../.../.../.../",
        "/../../../../../../../../../../../../etc/passwd",
        "/../../../../../../../../../../../../boot.ini",
        "..:..:..:..:..:..:..:..:..:..:..:..:..:",
        "\\\\*",
        "\\\\?\\",
        "/\\" * 5000,
        "/." * 5000,
        "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
        "%01%02%03%04%0a%0d%0aADSF",
        "%01%02%03@%04%0a%0d%0aADSF",
        "/%00/",
        "%00/",
        "%00",
        "%u0000",
        "%\xfe\xf0%\x00\xff",
        "%\xfe\xf0%\x01\xff" * 20,

        # format strings.
        "%n" * 100,
        "%n" * 500,
        "\"%n\"" * 500,
        "%s" * 100,
        "%s" * 500,
        "\"%s\"" * 500,

        # command injection.
        "|touch /tmp/SULLEY",
        ";touch /tmp/SULLEY;",
        "|notepad",
        ";notepad;",
        "\nnotepad\n",

        # SQL injection.
        "1;SELECT%20*",
        "'sqlattempt1",
        "(sqlattempt2)",
        "OR%201=1",

        # some binary strings.
        "\xde\xad\xbe\xef",
        "\xde\xad\xbe\xef" * 10,
        "\xde\xad\xbe\xef" * 100,
        "\xde\xad\xbe\xef" * 1000,
        "\xde\xad\xbe\xef" * 10000,
        "\x00" * 1000,

        # miscellaneous.
        "\r\n" * 100,
        "<>" * 500,		 # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt),
        "\xff"*100,
        "\xff"*1000,
        "\x7f"*100,
        "\x7f"*1000,
        ]
    for string in bad_strings:
        yield string

    for length in [128, 256, 1024, 2048, 4096, 32767, 0xFFFF]:
        s = "B" * length
        s = s[:len(s)/2] + "\x00" + s[len(s)/2:]
        yield(s)

    # TODO: add ShellShock test (+ reboot OS command)
    OS_commands = ["&&", "|"]
    OS_command = "sleep 30"

    add_long_strings("A")
    add_long_strings("B")
    add_long_strings("1")
    add_long_strings("2")
    add_long_strings("3")
    add_long_strings("<")
    add_long_strings(">")
    add_long_strings("'")
    add_long_strings("\"")
    add_long_strings("/")
    add_long_strings("\\")
    add_long_strings("?")
    add_long_strings("=")
    add_long_strings("a=")
    add_long_strings("&")
    add_long_strings(".")
    add_long_strings(",")
    add_long_strings("(")
    add_long_strings(")")
    add_long_strings("]")
    add_long_strings("[")
    add_long_strings("%")
    add_long_strings("*")
    add_long_strings("-")
    add_long_strings("+")
    add_long_strings("{")
    add_long_strings("}")
    add_long_strings("\x14")
    add_long_strings("\xFE")   # expands to 4 characters under utf16
    add_long_strings("\xFF")   # expands to 4 characters under utf16


def add_long_strings(sequence):
    for length in [128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                   32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
                   0xFFFF+2, 99999, 100000, 500000, 1000000]:
        long_string = sequence * length
        yield(long_string)
# TODO FIX GENERATOR: THERE is issueus about encoding/decoding
# TODO DELETE mod etc
# TODO OPTIMIZE with larger data


def basic_auth_generator(auth_string):
    yield auth_string
    delimiter = ":"
    prefix = "Basic"
    login, password = auth_string.strip("{} ".format(prefix)).decode('base64').split(delimiter)
    delim_gen = delimiter_generator(delimiter)
    while True:
        try:
            yield "{} {}".format(prefix, (login+delim_gen.next()+password).encode('base64'))[:-1]
        except StopIteration:
            break
    cred_gen = string_generator(login)
    while True:
        try:
            yield "{} {}".format(prefix, (cred_gen.next()+delimiter+password).encode('base64'))[:-1]
        except StopIteration:
            break
    cred_gen = string_generator(password)
    while True:
        try:
            yield "{} {}".format(prefix, (login+delimiter+cred_gen.next()).encode('base64'))[:-1]
        except StopIteration:
            break


def int_generator():
    yield 0
    for i in xrange(-5, 5):
        yield i

    power = 8
    while power <= 32:
        x = 2**(power-1) - 1
        for i in xrange(x - 10, x + 10):
            yield i
            yield -i
        x = 2**power - 1
        for i in xrange(x - 10, x + 10):
            yield i
            yield -i
        power *= 2
    yield 18446744073709551615
    yield 18446744073709551615*(-1)


def decimal_generator():
    for width in [BYTE, WORD, DWORD, QWORD]:
        max_num = int("1" * width)
        for integer in [0, max_num/2, max_num/3, max_num/4, max_num/8, max_num/16, max_num/32, max_num]:
            for i in xrange(-10, 10):
                case = integer + i
                if 0 <= case <= max_num:
                    yield case
                    yield case * (-1)


def range_generator():
    res = "bytes="
    yield "{}{}-{}".format(res, 0, 0)
    yield "{}{}-{}".format(res, "-0", "-0")
    yield "{}{}-{}".format(res, "-100", "-100")
    yield "{}{}-{}".format(res, "100", "-100")
    dec_gen = decimal_generator()
    while True:
        try:
            pos = dec_gen.next()
            yield "{}{}-{}".format(res, pos, 0)
            yield "{}{}-{}".format(res, 0, pos)
        except StopIteration:
            break
    pos = 0
    res = "bytes="
    byte_range = random.randint(2, 1000)
    chunk_len = random.randint(1, byte_range/2)
    x1 = 2**(8-1) - 1
    x2 = 2**(16-1) - 1
    for i in xrange(x1, x2):
        nextpos = pos + chunk_len
        res += "%d-%d," % (random.randint(0, nextpos), random.randint(0, nextpos))
        pos = nextpos
    yield res[:-1]
    # CHECK FOR BUGS!!!
    power = 8
    byte_range = random.randint(2, 1000)
    while power <= 16:
        pos = 0
        res = "bytes="
        x = 2**(power-1) - 1
        for i in xrange(x):
            res += "%d-%d," % (pos, byte_range)
        yield res[:-1]
        power *= 2


def blob_generator(blob):
    zzuf = pyZZUF(blob)
    yield blob
    # Very tricky seed value
    zzuf.set_seed(666)
    zzuf.set_fuzz_mode(FUZZ_MODE_XOR)
    for data in zzuf.mutagen(start=0.0, stop=1, step=0.001):
        yield data.tostring()


if __name__ == "__main__":
    delimiters = ["\r\n", ":", "/", "?", "=", "&", ",", ";"]
    basic_value = "\r\n".join(["OPTIONS /startPage HTTP/1.1",
                   "Connection: Keep-Alive",
                   "Accept-Charset: utf-8",
                   "Accept-Language: en-US,ru-RU",
                   "Cache-Control: s-maxage=1062309894735254426, no-store",
                   "Referer: 172.16.10.65:50000",
                   "Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, */*",
                   "Accept-Encoding: ",
                   "Content-Length: 0",
                   "Content-Type: application/x-www-form-urlencoded",
                   "Host: 172.16.10.65:50000",
                   "User-Agent: WebInterface",
                   "Range: bytes=0-1000",
                   "Authorization: Basic dXNlcjpwdWJsaWM="])





    #basic_gen = request_generator(basic_value)
    #print basic_gen
    #while True:
    #    try:
    #        print basic_gen.next()
    #        print "\r\n====\r\n"
    #    except StopIteration:
    #        break
