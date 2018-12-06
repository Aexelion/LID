#!/usr/bin/python3

import csv
# import geoip2.webservice
import whois
import socket
import ipaddress
import ssl
import whois
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


# def geolocaliser(ipAddr):
# 	ip = ipaddress.ip_address(ipAddr)
# 	if ip.version == 4:
# 		with open("BDD/GeoLite2-City-Blocks-IPv4.csv", newline='') as csvListIPv4:
# 			reader = csv.DictReader(csvListIPv4, delimiter=',')
# 			for ligne in reader :
# 				reseau = ipaddress.IPv4Network(ligne['network'])
# 				if ip in list(reseau.hosts()) :
# 					print(ligne['network'])
# 					return 0


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
	#geolocaliser('192.168.1.1')
	verifCertif('google.com')
	reservationDomaine('google.com')
	verifCertif('wikipedia.org')
	reservationDomaine('wikipedia.org')
	verifCertif('www.impots.gouv.fr')
	reservationDomaine('www.impots.gouv.fr')
