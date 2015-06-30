
##      ## ##     ## ######## ######## ######## ########
##  ##  ## ##     ##      ##       ##  ##       ##     ##
##  ##  ## ##     ##     ##       ##   ##       ##     ##
##  ##  ## ##     ##    ##       ##    ######   ########
##  ##  ## ##     ##   ##       ##     ##       ##   ##
##  ##  ## ##     ##  ##       ##      ##       ##    ##
 ###  ###   #######  ######## ######## ######## ##     ##
                                                                                           
Author: Andrey Plastunov
email: plastunovaa@gmail.com
twitter: @aplastunov
==========================================================

##      ## ######## ########  #######
##  ##  ##    ##    ##       ##     ##
##  ##  ##    ##    ##             ##
##  ##  ##    ##    ######       ###
##  ##  ##    ##    ##          ##
##  ##  ##    ##    ##
 ###  ###     ##    ##          ##


0x00 For now, the wuzzer isn't a complete tool, but rather a compilation of some ideas on http fuzzing,
which is somehow working
So it is only a pre-pre-pre-pre-pre release
At this very moment of time, the wuzzer's functionality is limited to:
- Some fuzzing primitives (mostly ripped off from Sulley framework (https://github.com/OpenRCE/sulley)
- A number of HTTP request header generators
- URL generator
- post data: application/x-www-form-urlencoded generator
- Some binary data mutators using pyZZUF (https://github.com/nezlooy/pyZZUF)
- Some crappy kind of logger
And also it can send data being generated!!! =)

To be added:
 - Additional header generators
 - post data: multipart generators
 - Proper monitoring module (+ erorr handling mechanism, session managment)
 - Nice and beatiful logger
 - PoC Generator
 - Response header generators
 - Reverse fuzzing mode

0x01 Wuzzer
<Some info to be added>


0x02 So how to use that thing?
usage: wuzzer.py [-h] [--threads THREADS] [--proxy PROXY]
                 [--mode {headers,post-data,url-data,whole-request,poc} [{headers,post-data,url-data,whole-request,poc} ...]]
                 [--method {HEAD,GET,POST,OPTIONS,PUT,DELETE,TRACE,CONNECT} [{HEAD,GET,POST,OPTIONS,PUT,DELETE,TRACE,CONNECT} ...]]
                 [--input {wuzzer,custom,pcap}] --target TARGET
                 [--delay DELAY] [--config CONFIG] [--output OUTPUT]

Wuzzer: The Dumbest HTTP fuzzer

optional arguments:
  -h, --help            show this help message and exit
  --threads THREADS     Number of threads for sending requests
  --proxy PROXY         Proxy's host:port, if required. Example:127.0.0.1:8080
  --mode {headers,post-data,url-data,whole-request,poc} [{headers,post-data,url-data,whole-request,poc} ...]
                        Fuzzing modes. By default 'headers' only will be
                        fuzzed
  --method {HEAD,GET,POST,OPTIONS,PUT,DELETE,TRACE,CONNECT} [{HEAD,GET,POST,OPTIONS,PUT,DELETE,TRACE,CONNECT} ...]
                        HTTP methods to test. (default: all available methods
  --input {wuzzer,custom,pcap}
                        Source of http request to fuzz
  --target TARGET       Target's host:port (default port: 80). Example:
                        www.google.com:80
  --delay DELAY         Delay between request. In seconds
  --config CONFIG       Name of the external config to use**
			In this case wuzzer should be configured via case_config.py file. Right now it already contain some examples and explanations
  --output OUTPUT       File to write fuzzing results

Additional info: 
- For now wuzzer's queue size is hardcode limited to 10000 elements
- Also there is some kind of status info, showing in stdout, which is updated every 20 seconds (hardcoded too)
** - Config should have the following structure to be parsed properly:
      <RAW REQEST 1>
      -=WUZZER_SEPARATOR=-
      <RAW REQEST 2>
      -=WUZZER_SEPARATOR=-
      ...
      <RAW REQEST n>
      -=WUZZER_SEPARATOR=-
Here <RAW REQEST n> is a plain request directly from the wires, e.g:
GET /very/long/path?param1=oh&param2=lol HTTP/1.1
Host: www.google.com:80
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://www.google.com/some/path/here/
Cookie: Some=cookies;
DNT: 1
Connection: keep-alive

0x03 Requirements
 - see the requirements.txt
