import pickle
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime


class caseLogger():

	case = None

	def __init__(self):
		self.case = []

	def writeCase(self,index,data):
		now = datetime.now()
		stamp = mktime(now.timetuple())
		self.case.append([index,stamp,data.encode('base64')])
		return 0

	def readCases(self):
		return self.case

	def toFile(self,filename):
		with open(filename, 'wb') as f:
			for c in self.case:
				str_ = "%d:%s:%s" % (c[0], str(c[1]), c[2])
				pickle.dump(str_,f)
		self.case = []
		return 0

	def fromFile(self,filename):
		with open(filename, 'rb') as f:
			while True:
				try:
					case_ = pickle.load(f)
					self.case.append(str(case_).split(':'))
					self.case[-1][2] = self.case[-1][2].decode('base64')
				except EOFError:
					break 
		#for c_ in case_:
		#	print c_
		return 0


if __name__ == '__main__':
	log = caseLogger()
	log.writeCase(1,'test1\npriver\r\npriver\r\npriver\r\npriver\r\npriver\r\n')
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
	log.writeCase(2,req)
	log.writeCase(3,'test3')
	log.toFile('test')
	log.fromFile('testcases')
	for case in log.readCases():
		print case[2]