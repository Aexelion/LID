#!/usr/bin/python3

import csv
import whois
import socket
import ipaddress
import ssl	
"""
Recherche de site de fishing parmis les sites '.org'
"""
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
	pass


def httpOnly(url):
	#get url2 from database
	url2 = 'something.com'
	if(len(url)!=len(url2)):
		pass #score + 0?
	else:
		count = sum(1 for a, b in zip(seq1, seq2) if a != b)


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




if __name__ == '__main__':
#	print(geolocaliser('123.45.67.89'))
	verifCertif('google.com')
	reservationDomaine('google.com')
	verifCertif('wikipedia.org')
	reservationDomaine('wikipedia.org')
	verifCertif('www.impots.gouv.fr')
	reservationDomaine('www.impots.gouv.fr')
