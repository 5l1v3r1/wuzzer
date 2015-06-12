"""THIS CONFIG FILE SHOULD BE USED IN ORDER TO FUZZ MULTIPLE OR NON-DEFAULT REQUESTS OR RESPONSES"""

"""
Section to describe HTTP requests to Fuzz
Each request should be described as an element of the following REQUESTS list
!IMPORTANT NOTE!
Payload segment of each request should be separated from headers with an empty string (see example in request1)
"""
request1 = "\r\n".join(["POST /admin/testPage.html?param1=why&param2=so&param3=serious&test=123 HTTP/1.1",
                        "Host: 127.0.0.1",
                        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:37.0) Gecko/20100101 Firefox/37.0",
                        "Accept: text/javascript, text/html, application/xml, text/xml, */*",
                        "Accept-Language: en-US,en;q=0.5",
                        "Accept-Encoding: gzip, deflate",
                        "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
                        "Referer: http://127.0.0.1/admin",
                        "Content-Length: 221",
                        "Cookie: JSESSION=D77CBCBC2D677102B2CB3F1A5DC4E10D; secret_cookie=1;",
                        "DNT: 1",
                        "Connection: keep-alive",
                        "Pragma: no-cache",
                        "Cache-Control: no-cache",
                        "",
                        "param1=hello&param2=world&test=azaza"])

REQUESTS = [request1]

"""
Section to describe HTTP responses to Fuzz
Each response should be described as an element of the following RESPONSES list
!IMPORTANT NOTE!
Payload segment of each response should be separated from headers with an empty string (see example in response1)
"""
response1 = "\r\n".join(["HTTP/1.1 200 OK",
                         "Content-Type: text/html; charset=UTF-8",
                         "Set-Cookie: PREF=ID=b039e274241a3775:FF=0:NW=1:TM=1434041626:LM=1434041626:S=Xi9drNILxUXBT-pF; expires=Sat, 10-Jun-2017 16:53:46 GMT; path=/; domain=.google.ru",
                         "Set-Cookie: NID=68=GEW7Jjd-WzsKrN9FFiC9bpEwZDr7zngFxW1yuvrENCguvMEHJIgaPRNUWjma39z2KEmXYqRq5c6Z2K_Tn8AjfFdSUG6RmKYz56m31aNRfL51JSGYnTq3ISBnpS5ik0Qf; expires=Fri, 11-Dec-2015 16:53:46 GMT; path=/; domain=.google.ru; HttpOnly",
                         "P3P: CP=\"This is not a P3P policy! See http://www.google.com/support/accounts/bin/answer.py?hl=en&answer=151657 for more info.\"",
                         "Date: Thu, 11 Jun 2015 16:53:46 GMT",
                         "Server: gws",
                         "Cache-Control: private",
                         "X-XSS-Protection: 1; mode=block",
                         "X-Frame-Options: SAMEORIGIN",
                         "Expires: Thu, 11 Jun 2015 16:53:46 GMT",
                         "Alternate-Protocol: 80:quic,p=0",
                         "Content-Length: 4",
						 "",
						 "test"])

RESPONSES = [response1]
