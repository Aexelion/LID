#!/usr/bin/python3
import logging
import sys
import datetime
import certstream
import queue
import analyse
import time
import stix2

geoLoc = False

def print_callback(message, context):
	logging.debug("Message -> {}".format(message))

	if message['message_type'] == "heartbeat":
		return
	
	if message['message_type'] == "certificate_update":
		all_domains = message['data']['leaf_cert']['all_domains']

		if len(all_domains) == 0:
			domain = "NULL"
		else:
			domain = all_domains[0]
		
		if '.org' in domain or '.gouv.fr' in domain:
#			print(domain)
			tmp = (u"[{}] {} (SAN: {})".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
			score = lescriptdetest(domain, geoLoc)
			
			ts = time.time()
			st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
#			print(tmp + " - Score : " + str(score))
			
			if score < 50:
				indicator = stix2.Indicator(
					labels=["benine site","score="+str(score)],
					pattern="[url:value = '" + domain + "']"
				)
#				print(indicator)
			elif score < 300:
				indicator = stix2.Indicator(
					labels=["potential phishing","score="+str(score)],
					pattern="[url:value = '" + domain + "']"
				)
#				print(indicator)
			elif score < 700:
				indicator = stix2.Indicator(
					labels=["probable phishing","score="+str(score)],
					pattern="[url:value = '" + domain + "']"
				)
#				print(indicator)
			else :
				indicator = stix2.Indicator(
					labels=["highly probable phishing","score="+str(score)],
					pattern="[url:value = '" + domain + "']"
				)
#				print(indicator)
			
			
			




def lescriptdetest(domain, geoLoc=False):
	analyse.virusTotalScan(domain)
	score = 0
	score += analyse.reject(domain)*2
	score += analyse.verifCertif(domain)*2
	score += analyse.verifVariation(domain)
	score += analyse.reservationDomaine(domain)
	score += analyse.virusTotalReport(domain)*4
	if geoLoc and '.gouv.fr' in domain:
		score += analyse.geoScore(domain, wList=[France])
	return score
		
	
	
	
if __name__ == '__main__' :
	test = input("Voulez-vous activer la géolocalisation des différents sites, cela augmente légèrement le processus (jusqu'à 1 minute) ? o/N ").upper()
	geoLoc = False
	while not(test == 'O' or test == 'N' or test == ''):
		print('Input invalide')
		test = input("Voulez-vous activer la géolocalisation des différents sites, cela augmente légèrement le processus (jusqu'à 1 minute) ? o/N ").upper()
	if test == 'O':
		geoLoc = True
	logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
	certstream.listen_for_events(print_callback,"wss://certstream.calidog.io")
	


	
