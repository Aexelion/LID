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
Recherche de site de fishing parmis les sites '.org' et '.gouv.fr'
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


def geoScore(url, wList=[], bList=[]):
	ip = socket.gethostbyname(url)
	loc = geolocaliser(ip)
	if (loc[0] in bList) or (loc[1] in bList):
		return 100
	elif loc[0] in wList or loc[1] in wList:
		return 0
	else :
		return 50


def variationURL(url, url2):
		count = sum(1 for a, b in zip(url, url2) if a != b)
		return count


def verifVariation(url):
	with open("top-1m.csv", newline='') as siteRef:
		read = csv.reader(siteRef, delimiter=',')
		mini = 1000000
		score = 0
		for ligne in read:
			nbVar = variationURL(url, ligne[1])
			if(nbVar==3 and url.split('.',2)[1]==ligne[1].split('.',1)[0] and url.split('.',1)[1]!=ligne[1].split('.',1)[1]):
				score = 100
				return score
			else:
				if nbVar < mini :
					mini = nbVar
		if(mini==1):
			score = 100
		if(mini==2):
			score = 50
		if(mini==3):
			score = 20
		return score

def virusTotalScan(url):
	params = {'apikey': 'c8d66d5d8ea2e078f31e20b501e21aa5b55d9da07c72d8b49456fb202de725fc', 'url':url}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
	json_response = response.json()
#	print('scan of '+url+' : ')
#	print(json_response)

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
		count = 0
		for x in json_response['scans']:
			if(json_response['scans'][x]['detected']==True):
#				print('anomaly detected : ')
#				print(json_response['scans'][x]['result'])
#				print('\n')
				count += 1
		return count
	else:
#		print('nothing suspect found')
		return 0


def reservationDomaine(url):
	score = 0
	whoisdom = whois.whois(url)
	dt = whoisdom.creation_date
	try:
		if(dt[0] == None):
			score=100
			return score
		delta = datetime.datetime.now()-dt[0]
		if(delta.days<2):
			score=90
		elif(delta.days<4):
			score=70
		elif(delta.days<7):
			score=50
		elif(delta.days<14):
			score=25
		elif(delta.days<20):
			score=10
		else:
			score=0
	except:
		if(dt == None):
			score=100
			return score
		delta = datetime.datetime.now()-dt
		if(delta.days<2):
			score=90
		elif(delta.days<4):
			score=70
		elif(delta.days<7):
			score=50
		elif(delta.days<14):
			score=25
		elif(delta.days<20):
			score=10
		else:
			score=0
	return score

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
		dt = time.strptime(validity_end[:-4], "%b %d %H:%M:%S %Y")
		date_end = datetime.datetime(dt[0],dt[1],dt[2])
		delta = datetime.datetime.now()-date_end
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
		return score
	except:
		score=100
		return score

def reject(url):
	with open("BDD/reject.txt", newline='') as rejectedDomain:
		for ligne in rejectedDomain:
			if url in ligne:
				return 100



if __name__ == '__main__':
#	print(geolocaliser('123.45.67.89'))
	#virusTotalScan('google.com')
	#virusTotalScan('www.impots.gouv.fr')
	#verifCertif('google.com')
	#reservationDomaine('google.com')
	#verifCertif('wikipedia.org')
	reservationDomaine('wikipedia.org')
	verifVariation('wikipedia.org')
	#verifCertif('www.impots.gouv.fr')
	#reservationDomaine('www.impots.gouv.fr')
	#virusTotalReport('google.com')
	#virusTotalReport('www.impots.gouv.fr')
	#url = 'amazon.co.uk.security-check.ga'
	#scoreMaker(url)
	#virusTotalScan('amazon.co.uk.security-check.ga')
	#verifCertif('amazon.co.uk.security-check.ga')
	#reservationDomaine('amazon.co.uk.security-check.ga')
	#virusTotalReport('amazon.co.uk.security-check.ga')
