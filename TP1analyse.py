import logging
import sys
import datetime
import certstream
import queue
import analyse

#exQ = queue()

def print_callback(message, context):
	logging.debug("Message -> {}".format(message))

	if message['message_type'] == "heartbeat":
		return

#	test = input("Voulez-vous activer la géolocalisation des différents sites, cela augmente légèrement le processus (jusqu'à 1 minute) ? o/N ").upper()
#	geoLoc = False
#	while not(test == 'O' or test == 'N' or test == ''):
#		print('Input invalide')
#		test = input("Voulez-vous activer la géolocalisation des différents sites, cela augmente légèrement le processus (jusqu'à 1 minute) ? o/N ").upper()
#	if test == 'O':
#		geoLoc = True

	if message['message_type'] == "certificate_update":
		all_domains = message['data']['leaf_cert']['all_domains']

		if len(all_domains) == 0:
			domain = "NULL"
		else:
			domain = all_domains[0]
		if '.org' in domain or '.gouv.fr' in domain:
			tmp = (u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
			score = lescriptdetest(domain, False)





def lescriptdetest(domain, geoLoc=False):
	score = 0
	score += analyse.reject(domain)
	score += verifCertif(domain)
	score += verifVariation(domain)
	if geoLoc and '.gouv.fr' in domain:
		score += geoScore(domain, wList=[France])




if __name__ == '__main__' :
	logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
	certstream.listen_for_events(print_callback,"wss://certstream.calidog.io")
