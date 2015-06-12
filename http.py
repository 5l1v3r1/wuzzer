# Dumb implementation of mitmproxy/netlib/http
# Original's GitHub: https://github.com/mitmproxy/netlib/tree/master/netlib


class HttpError(Exception):
	def __init__(self, code, message):
		super(HttpError, self).__init__(message)
		self.code = code

def _is_valid_port(port):
	if not 0 <= port <= 65535:
		return False
	return True


def _is_valid_host(host):
	try:
		host.decode("idna")
	except ValueError:
		return False
	if "\0" in host:
		return None
	return True

def parse_http_protocol(s):
	"""
		Parse an HTTP protocol declaration. Returns a (major, minor) tuple, or
		None.
	"""
	if not s.startswith("HTTP/"):
		return None
	_, version = s.split('/', 1)
	if "." not in version:
		return None
	major, minor = version.split('.', 1)
	try:
		major = int(major)
		minor = int(minor)
	except ValueError:
		return None
	return "HTTP/%d.%d"%(major,minor)

def parse_response_line(line):
	parts = line.strip().split(" ", 2)
	if len(parts) == 2:  # handle missing message gracefully
		parts.append("")
	if len(parts) != 3:
		return None
	proto, code, msg = parts
	try:
		code = int(code)
	except ValueError:
		return None
	return (proto, code, msg)

def parse_headers(data):
	ret = []
	name = ''
	for line in data.split('\r\n')[1:]:
		if not line or line == '\r\n' or line == '\n':
			break
	#WTFO_o
	#   if line[0] in ' \t':
	#	   if not ret:
	#		   return None
	#	   # continued header
	#		ret[-1][1] = ret[-1][1] + '\r\n ' + line.strip()
	#	else:
		i = line.find(':')
		# We're being liberal in what we accept, here.
		if i > 0:
			name = line[:i]
			value = line[i + 1:].strip()
			ret.append([name, value])
		else:
				return None
	return ret

#def parse_body(data):

def read_response(data):
	"""
		Return an (httpversion, code, msg, headers, content) tuple.

		By default, both response header and body are read.
		If include_body=False is specified, content may be one of the following:
		- None, if the response is technically allowed to have a response body
		- "", if the response must not have a response body (e.g. it's a response to a HEAD request)
	"""
	response_line = ''.join((data.split('\r\n')[0:1]))
	#print "[DEBUG] HTTP RESPONSE LINE: %s"%(response_line)
	parts = parse_response_line(response_line)
	if not parts:
		raise HttpError(502, "Invalid server response: %s" % repr(response_line))
	proto, code, msg = parts
	httpversion = parse_http_protocol(proto)
	if httpversion is None:
		raise HttpError(502, "Invalid HTTP version in line: %s" % repr(proto))
	headers = parse_headers(data)
	if headers is None:
		raise HttpError(502, "Invalid headers.")
	return httpversion, code, msg, headers

	
def parse_request_line(line):
	parts = line.strip().split(" ", 2)
	if len(parts) == 2:  # handle missing message gracefully
		parts.append("")
	if len(parts) != 3:
		return None
	method, path, proto = parts
	return (method, path, proto)
	
def read_request_from_file(data):
	"""
		Return an (httpversion, code, msg, headers, content) tuple.

		By default, both response header and body are read.
		If include_body=False is specified, content may be one of the following:
		- None, if the response is technically allowed to have a response body
		- "", if the response must not have a response body (e.g. it's a response to a HEAD request)
	"""
	request_line = ''.join((data.split('\r\n')[0:1]))
	#print "[DEBUG] HTTP RESPONSE LINE: %s"%(response_line)
	parts = parse_request_line(request_line)
	if not parts:
		return ""
	method, path, proto = parts
	httpversion = parse_http_protocol(proto)
	if httpversion is None:
		raise HttpError(502, "Invalid HTTP version in line: %s" % repr(proto))
	headers = parse_headers(data)
	if headers is None:
		raise HttpError(502, "Invalid headers.")
	return method, path, httpversion, headers

	
#if __name__ == "__main__":
