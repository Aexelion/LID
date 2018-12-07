#!/usr/bin/python3

import csv
import whois
import socket
import ipaddress
import ssl
import requests
import time
import datetime
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


def geoScore(url, wList=[], bList=[]):
	ip = socket.gethostbyname(url)
	loc = geolocaliser(ip)
	if (loc[0] in bList) or (loc[1] in bList):
		return 100
	elif loc[0] in wList or loc[1] in wList:
		return 0
	else :
		return 50


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
	if(json_response['positives'] != 0):
		for x in json_response['scans']:
			if(json_response['scans'][x]['detected']==True):
				print('anomaly detected : ')
				print(json_response['scans'][x]['result'])
				print('\n')
	else:
		print('nothing suspect found')


def reservationDomaine(url):
	whoisdom = whois.whois(url)
	date_exp_domain = whoisdom.expiration_date
	date_cre_domain = whoisdom.creation_date
	hebergeur = whoisdom.registrar
	print(date_cre_domain,date_exp_domain)


<<<<<<< HEAD

=======
>>>>>>> 92c22ca54b9467c8abc4201ce2577c42790aad6d
def distance(url):
	pass

dMonth={'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def verifCertif(url):
	try:
		hostname = url
		context = ssl.create_default_context()
		sock = context.wrap_socket(socket.socket(), server_hostname=hostname)
		sock.connect((hostname, 443))
		certificate = sock.getpeercert()
		issuer = dict(x[0] for x in certificate['issuer'])
		issued_by = issuer['commonName']
		validity_end = certificate['notAfter']
		version = certificate['version']
		#print(validity_end)
		##list of trusted certification authority
		##list of rejected certification authority
		date_end = datetime.strptime(validity_end[:-4], "%b %d %H:%M:%S %Y")
		print(date_end)
		print(datetime.datetime.now())
		delta = datetime.datetime().now()-date_end
		delta2 = date_end - datetime.datetime.now()
		print(delta)
		print(delta2)
		score = 0
		if(delta.days>30):
			score=80
		elif(delta.days>7):
			score=60
		elif(delta.days>4):
			score=40
		elif(delta.days>0):
			score=20
		else:
			score=0
		print(score)
		return score
		# if(validity_end[-8:-4]<time.localtime()[0]):
		# 	score = 80
		# elif(validity_end[-8:-4]==time.localtime()[0])
		# 	if(dMonth[validity_end[:3]]-time.localtime()[1]<-1):
		# 		score-=20
		# 	elif(dMonth[validity_end[:3]]-time.localtime()[1]>=-1):

	except:
		pass

def reject(url):
	with open("BDD/reject.txt", newline='') as rejectedDomain:
		for ligne in rejectedDomain:
			if url in ligne:
				return 100



if __name__ == '__main__':
#	print(geolocaliser('123.45.67.89'))
<<<<<<< HEAD
	# virusTotalScan('google.com')
	# virusTotalScan('www.impots.gouv.fr')
	verifCertif('google.com')
	#reservationDomaine('google.com')
	verifCertif('wikipedia.org')
	#reservationDomaine('wikipedia.org')
	verifCertif('www.impots.gouv.fr')
	#reservationDomaine('www.impots.gouv.fr')
	# virusTotalReport('google.com')
	# virusTotalReport('www.impots.gouv.fr')
	#url = 'amazon.co.uk.security-check.ga'
	#virusTotalScan('amazon.co.uk.security-check.ga')
	#verifCertif('amazon.co.uk.security-check.ga')
	#reservationDomaine('amazon.co.uk.security-check.ga')
	#virusTotalReport('amazon.co.uk.security-check.ga')
=======
#	 virusTotalScan('google.com')
#	 virusTotalScan('www.impots.gouv.fr')
#	 verifCertif('google.com')
#	 reservationDomaine('google.com')
#	 verifCertif('wikipedia.org')
#	 reservationDomaine('wikipedia.org')
#	 verifCertif('www.impots.gouv.fr')
#	 reservationDomaine('www.impots.gouv.fr')
#	 virusTotalReport('google.com')
#	 virusTotalReport('www.impots.gouv.fr')
	url = 'amazon.co.uk.security-check.ga'
	scoreMaker(url)
	virusTotalScan('amazon.co.uk.security-check.ga')
	verifCertif('amazon.co.uk.security-check.ga')
	reservationDomaine('amazon.co.uk.security-check.ga')
	virusTotalReport('amazon.co.uk.security-check.ga')
>>>>>>> 92c22ca54b9467c8abc4201ce2577c42790aad6d
