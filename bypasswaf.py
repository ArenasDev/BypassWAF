import sys
import validators
import subprocess
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import argparse
import numpy as np
from termcolor import colored
from requests_html import AsyncHTMLSession
from bs4 import BeautifulSoup
from prettytable import PrettyTable, PLAIN_COLUMNS

global domain
global session
global reference
global results
global args
headers = ['Date', 'Cache-Control', 'Content-Type', 'Vary', 'Server', 'X-AspNetMvc-Version', 'X-AspNet-Version', 'X-Powered-By', 'Connection', 'Content-Length', 'Last-Modified', 'Accept-Ranges', 'Access-Control-Allow-Origin', 'edge-control', 'X-UA-Compatible', 'Expires', 'X-XSS-Protection', 'X-Frame-Options', 'Content-Security-Policy', 'ETag', 'Location', 'Content-Encoding']

async def securityTrails():
	global domain

	print(colored('[+] Checking securityTrails ...', 'green', attrs=['bold']))
	asession = AsyncHTMLSession()
	sp = BeautifulSoup((await asession.get('https://securitytrails.com/domain/' + domain.split('/')[2] + '/history/a', verify=False)).text , "lxml")
	return np.unique([ip['href'][9:] for ip in sp.find_all('a', href=True) if '/list/ip/' in ip['href']])

async def viewDNSdotInfo():
	global domain

	print(colored('[+] Checking viewDNS.info ...', 'green', attrs=['bold']))
	asession = AsyncHTMLSession()
	sp = BeautifulSoup((await asession.get('https://viewdns.info/iphistory/?domain=' + domain.split('/')[2], verify=False)).text , "lxml")
	return np.unique([ip.text for ip in sp.find_all('td') if validators.ip_address.ipv4(ip.text)])

async def checkIP(ip):
	global domain, reference, results, args

	headers = {'Host': domain.split('/')[2]}
	asession = AsyncHTMLSession()

	try:
		r = await asession.get(domain.split('/')[0] + '//' + ip, headers=headers, verify=False, cookies={}, allow_redirects=False, timeout=args.t)
		if r.status_code == reference.status_code:
			if checkWAF(cleanHeaders(r)):
				print(colored('[+] Possible bypass in IP ' + ip, 'yellow', attrs=['bold']))
	except Exception as e:
		if 'ConnectTimeoutError' in str(e):
			print(colored('[!] Timeout (' + str(args.t) + 's) on connection with IP ' + ip, 'red', attrs=['bold']))
		elif 'Max retries' in str(e):
			print(colored('[!] Maximum retries exceeded on connection with IP ' + ip, 'red', attrs=['bold']))
		else:
			print(e)

def checkWAF(r):
	global reference, args
	#TODO
	ret = True
	if len(r.headers) == len(reference.headers):
		for header in reference.headers:
			if r.headers.get(header, -1):
				if header.lower() == 'set-cookie':
					for name in reference.cookies.keys():
						if name not in r.cookies.keys():
							if args.v:
								print(colored('[V] Cookie not in new response:', 'yellow', attrs=['bold']))
								printDiff(reference, r, 'cookies')
							ret = True
							break
						else:
							ret = False			
			else:
				ret = True
				if args.v:
					print(colored('[V] Header missing in new response:', 'yellow', attrs=['bold']))
					printDiff(reference, r, 'headers')
	else:
		ret = True
		if args.v:
			print(colored('[V] Different number of headers', 'yellow', attrs=['bold']))
			printDiff(reference, r, 'headers')
	return ret

def printDiff(reference, r, field):
	print(colored('\tReference request: ', 'yellow', attrs=['bold']))
	for item in getattr(reference, field).keys():
		if item not in getattr(r, field).keys():
			print(colored('\t\t' + item, 'yellow', attrs=[]))
		else:
			print(colored('\t\t' + item, 'yellow', attrs=['bold']))
	print(colored('\tNew request: ', 'yellow', attrs=['bold']))
	for item in getattr(r, field).keys():
		if item not in getattr(reference, field).keys():
			print(colored('\t\t' + item, 'yellow', attrs=[]))
		else:
			print(colored('\t\t' + item, 'yellow', attrs=['bold']))

def cleanHeaders(h):
	newHeaders = {}
	for key in h.headers:
		newHeaders[key.lower()] = h.headers[key]
	h.headers = newHeaders

	for header in headers:
		h.headers.pop(header.lower(), None)

	cookies = {}
	for cookie in h.cookies.keys():
		name = ''.join(filter(lambda x: x.isalpha(), cookie))
		if name not in cookies.keys():
			cookies[''.join(filter(lambda x: x.isalpha(), cookie))] = h.cookies[cookie]
	h.cookies = cookies

	return h

async def getReferenceHeaders():
	global domain

	asession = AsyncHTMLSession()
	return await asession.get(domain, verify=False, cookies={}, allow_redirects=False)

if __name__ == "__main__":
	global domain, reference, results, args
	asession = AsyncHTMLSession()

	parser = argparse.ArgumentParser(description='Basic tool to check if it is possible to access a domain directly, bypassing WAFs')
	parser.add_argument('-u', default='', help='URL to test', required=True)
	parser.add_argument('-v', default=False, help='Verbose mode', required=False, action='store_true')
	#parser.add_argument('-r', default=3, help='Maximum retries of connection with new IPs', required=False, type=int)
	parser.add_argument('-t', default=5, help='Timeout in seconds of connection with new IPs', required=False, type=int)
	args = parser.parse_args()

	if args.u == '':
		#print('[!] Usage: python3 bypasswaf.py [http://|https://]domain.com')
		parser.print_help()
	else:
		domain = args.u
		if ('http://' in domain or 'https://' in domain) and validators.domain(domain.split('/')[2]):
			reference = cleanHeaders(asession.run(getReferenceHeaders)[0])

			results = []
			for l in asession.run(viewDNSdotInfo, securityTrails):
				for ip in l:
					results.append(ip)

			print(colored('[+] Gathering results ...', 'green', attrs=['bold']))

			asession = AsyncHTMLSession()
			asession.run(*[lambda ip=ip: checkIP(ip) for ip in results])
			#asession.run(checkIP)

			print(colored('Complete list of unique IPs (for manual testing) in /etc/hosts format:', 'green', attrs=['bold']))

			pt = PrettyTable()
			pt.set_style(PLAIN_COLUMNS)
			pt.header = False
			pt.field_names = ["IP", "Domain"]
			pt.align["IP"] = "l"

			for r in results:
				#print(colored('#' + r + '\t\t' + domain.split('/')[2], 'green', attrs=['bold']))
				pt.add_row(['#' + r, domain.split('/')[2]])

			print(pt)

		else:
			print(colored('[-] URL is not valid. It must be like [http://|https://]domain.com', 'red', attrs=['bold']))
			parser.print_help()
