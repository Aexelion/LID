#!/usr/bin/python3

import csv
# import geoip2.webservice
import whois
import socket
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

creationCSV("site-org",".org")
creationCSV("site-gouvfr","gouv.fr")


# def geolocaliser(ipAddr):
# 	with open("BDD/GeoLite2-City-Blocks-IPv4.csv", csv='') as csvListIPv4:
# 		reader = csv.reader(csvListIPv4, delimiter=',')
# 		for ligne in reader :
# 			if ipAddr = ligne['network'] :
# 				pass
# 	pass


def variationURL(url):
	pass


def httpOnly(url):
	pass


def reservationDomaine(url):
	"""Renvois la date"""
	pass


def reputation(url):
	"""Verifie la CA, l'IP et l'AS"""
	IPaddr = socket.gethostbyname(url)

	pass


def distance(url):
	pass


def verifCertif(url):

	pass


#if __name__ == '__main__':
#	geolocaliser('192.168.1.1')
