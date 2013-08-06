#!/usr/bin/env python

from operator import itemgetter
from datetime import datetime
from time import mktime
import time
import argparse
import pprint
import json

# Shodan API key here, this one won't work for you... sorry.
SHODAN_KEY = "aqn4baqSaqqtmcv25q7hQNxe1by6aG9P"
is_https = False
query = ""
api = None
fmt = "%Y-%m-%dT%H:%M:%S.%f"

def add_query(arg, key=None):
	if arg:
		global query
		if key is 'country':
			query += ' %s:%s' % (key, arg)
		elif not key:
			query += ' "%s"' % arg
		else:
			query += ' %s:"%s"' % (key, arg)

def search_query(limit, output):
	print "[+] New query is: %s\n" % query
        try:
		if limit:
	                res = api.search(query, limit=limit)
		else:
			res = api.search(query)
                print "\t[+] %s results found!\n" % res['total']
                #for country in res['countries']:
                #        print "\t[*] (%s) %s: %s\n" % (country['code'], country['name'], country['count'])
		for match in res['matches']:
			if output:
				with open(output, 'a') as fp:
					fp.write(json.dumps(match, indent=4, sort_keys=True))
					

	except Exception as e:
		print "[-] ERROR: %s" % e		

def search_host(host, output):
	fp = None
	if output:
		fp = open(output, 'a')

	res = api.host(host)
	txt = """[+] Host info is:\n
			IP: %s\n
			Country: %s\n
			City: %s\n
			OS: %s\n
			LONGITUDE: %s\n
			LATITUDE: %s\n\n""" % (res['ip'], res['country_name'], res['city'], res['os'], res['longitude'], res['latitude'])
	print txt
	if fp:
		fp.write(txt)

	set = sort_results(res['data'])
	for srv in set:
	        txt = "v"*60
	        txt += "\nPORT | %d\nBANNER | %s\nLAST UPDATE | %s\n" % (srv['port'], srv['banner'], srv['last_update'])
		txt += "^"*60
		print txt
		if fp:
			fp.write(txt)

	if fp:
		fp.close()

def sort_results(data):
	# Sort per port
	list = sorted(data, key=itemgetter('port'))
	list = list[::-1]
	port = 0
	ret = []
	for item in list:
		if item['port'] != port:
			port = item['port']
			ret.append(item)
	return ret

def main():
	try:
		from shodan import WebAPI
		from shodan.api import WebAPIError
	except ImportError, e:
		msg = "\nThis script is intended for you to use Shodan's WebAPI through\n"
		msg += "your console. We need the shodan library for this.\n\n"
		msg += "Install using easy_install [easy_install shodan] or please refer to:\n"
		msg += "http://docs.shodanhq.com/python/tutorial.html#installation\n"
		print msg
		return

	#TODO: geo, before/after, cert_bits, cipher_name, cipher_bits, cipher_protocol
	parser = argparse.ArgumentParser(
			description="SHODAN search client - Written by salcho. salchoman@gmail.com", 
			usage="%(prog)s [options] query", 
			add_help=True, 
			epilog="Example: shod.py -C JP -c Tokyo -o windows -q 'IIS 5'"
			)
	parser.add_argument("-l", "--limit", help="Limit number of results! [recommended]")
	parser.add_argument("-out", "--output", help="Output log file")

	gral = parser.add_argument_group("General")
	gral.add_argument("-C", "--country", help="Filter by country code [CO,US,JP,...]")
	gral.add_argument("-c", "--city", help="Filter by city")
	gral.add_argument("-n", "--net", help="Filtrar by CIDR subnet [x.x.x.x/y]")
	gral.add_argument("-o", "--os", help="Filter by OS")
	gral.add_argument("-p", "--port", help="Filter by port")

	#only with https add-on
	ssl = parser.add_argument_group("SSL")
	ssl.add_argument("-cv", "--cert-version", help="Filter by SSL version", choices=['Original', 'SSLv2', 'SSLv3', 'TLSv1'])
	ssl.add_argument("-ci", "--cert-issuer", help="Filter by CA")
	ssl.add_argument("-cd", "--cert-subject", help="Filter by cert description")

	excl = parser.add_mutually_exclusive_group(required=True)
	excl.add_argument("-H", "--hostname", help="Filter by host")
	excl.add_argument("-q", "--query", help="Query")

	args = parser.parse_args().__dict__

	print "\n[+] Shodan HQ search client - Written by salcho"
	print "[+] Starting API with key %s" % SHODAN_KEY
	global api
	api = WebAPI(SHODAN_KEY)
	try:
		inf = api.info()
	except WebAPIError as e:
		msg = "\n[-] WebAPIError! Message is: " + str(e)
		msg += "\n[-] Your key may be causing this. You may want to change it.\n"
		print msg
		return

	print "[+] Account info is:\n"
	for key in inf.keys():
		print "\t[*] %s: %s" % (key, inf[key])
		if key == 'https' and inf[key]:
			is_https = True

	if not is_https:
		del args['cert_version']
		del args['cert_issuer']
		del args['cert_subject']

	if not args['output']:
		print "[-] WARNING: Output file is not selected. Won't write results to disk"

	print "\n[*] Calling shodan service...\n"
	if args['hostname']:
		search_host(args['hostname'], args['output'])
	else:
		add_query(args['query'])
		for key, val in args.items():
			if val and key != 'limit' and key != 'query' and key != 'output':
				add_query(val, key=key)
		search_query(args['limit'], args['output'])

main()	

