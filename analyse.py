#!/usr/bin/python3

import csv
import whois
import socket
import ipaddress
import ssl
import requests
"""
Recherche de site de fishing parmis les sites '.org'
"""

def scoreMaker(url):
	scoreOfUrl = (url,0)
	return scoreOfUrl

def scoreModifier(scoreOfUrl, danger_p):
	scoreOfUrl = (scoreOfUrl[0],scoreOfUrl[1]+danger_p)
	return scoreOfUrl


def creationCSV(filename,type):
	with open('top-1m.csv', newline='') as csvIn:
		with open(filename+'.csv', 'w', newline='') as csvOut:
			reader = csv.reader(csvIn, delimiter=',')
			writer = csv.writer(csvOut, delimiter=',')
			for ligne in reader:
				if type in ligne[1]:
					writer.writerow(ligne)


def geolocaliser(ipAddr):
 	ipInterface = ipaddress.ip_interface(ipAddr)
 	codePays = -1
 	if ipInterface.version == 4 and ipInterface.ip.is_global:
 		with open("BDD/GeoLite2-City-Blocks-IPv4.csv", newline='') as csvListIPv4:
 			reader = csv.DictReader(csvListIPv4, delimiter=',')
 			for ligne in reader :
 				reseau = ipaddress.IPv4Network(ligne['network'])
 				if reseau.overlaps(ipInterface.network) :
 					codePays = ligne['geoname_id']
 					break
 	elif ipInterface.version == 6 and ipInterface.ip.is_global:
 		with open("BDD/GeoLite2-City-Blocks-IPv6.csv", newline='') as csvListIPv6:
 			reader = csv.DictReader(csvListIPv6, delimiter=',')
 			for ligne in reader :
 				reseau = ipaddress.IPv6Network(ligne['network'])
 				if reseau.overlaps(ipInterface.network) :
 					codePays = ligne['geoname_id']
 	if codePays != -1:
 		with open("BDD/GeoLite2-City-Locations-fr.csv", newline='') as codeCSV:
 			reader = csv.DictReader(codeCSV, delimiter=',')
 			for ligne in reader :
 				if codePays == ligne['geoname_id']:
 					return (ligne['continent_name'],ligne['country_name'])


def variationURL(url):
	#get url2 from database
	url2 = 'something.com'
	if(len(url)!=len(url2)):
		pass #score + 0?
	else:
		count = sum(1 for a, b in zip(seq1, seq2) if a != b)


def virusTotalScan(url):
	params = {'apikey': 'c8d66d5d8ea2e078f31e20b501e21aa5b55d9da07c72d8b49456fb202de725fc', 'url':url}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
	json_response = response.json()
	print('scan of '+url+' : ')
	print(json_response)

def virusTotalReport(url):
	headers = {
  		"Accept-Encoding": "gzip, deflate",
  		"User-Agent" : "gzip,  My Python requests library example client or username"
  		}
	params = {'apikey': 'c8d66d5d8ea2e078f31e20b501e21aa5b55d9da07c72d8b49456fb202de725fc', 'resource':url}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
	params=params, headers=headers)
	json_response = response.json()
	print('report of '+url+' : ')
	print(json_response)


def reservationDomaine(url):
	whoisdom = whois.whois(url)
	date_exp_domain = whoisdom.expiration_date
	date_cre_domain = whoisdom.creation_date
	hebergeur = whoisdom.registrar
	print(date_cre_domain,date_exp_domain)


def reputation(url):
	"""Verifie la CA, l'IP et l'AS"""
	ipAddr = socket.gethostbyname(url)



def distance(url):
	pass


def verifCertif(url):
	try:
		hostname = url
		context = ssl.create_default_context()
		sock = context.wrap_socket(socket.socket(), server_hostname=hostname)
		sock.connect((hostname, 443)) #try?
		certificate = sock.getpeercert()
		subject = dict(x[0] for x in certificate['subject'])
		issued_to = subject['commonName']
		issuer = dict(x[0] for x in certificate['issuer'])
		issued_by = issuer['commonName']
		validity_start = certificate['notBefore']
		validity_end = certificate['notAfter']
		version = certificate['version']
		print(issued_to)
		print(issued_by)
		print(validity_start)
		print(validity_end)
	except:
		pass

def reject(url):
	with open("BDD/reject.txt", newline='') as rejectedDomain:
		for ligne in rejectedDomain:
			if url in ligne:
				return 0 # TODO Mettre un score qu'il faut return



if __name__ == '__main__':
#	print(geolocaliser('123.45.67.89'))
	# virusTotalScan('google.com')
	# virusTotalScan('www.impots.gouv.fr')
	# verifCertif('google.com')
	# reservationDomaine('google.com')
	# verifCertif('wikipedia.org')
	# reservationDomaine('wikipedia.org')
	# verifCertif('www.impots.gouv.fr')
	# reservationDomaine('www.impots.gouv.fr')
	# virusTotalReport('google.com')
	# virusTotalReport('www.impots.gouv.fr')
	url = 'amazon.co.uk.security-check.ga'
	scoreMaker(url)
	virusTotalScan('amazon.co.uk.security-check.ga')
	verifCertif('amazon.co.uk.security-check.ga')
	reservationDomaine('amazon.co.uk.security-check.ga')
	virusTotalReport('amazon.co.uk.security-check.ga')
