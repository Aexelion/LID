

def resdom(url):
    whoisurl = whois.whois(url)
    ca_exp = whoisurl.expiration_date
    ca_cre = whoisurl.creation_date
    heb = whoisurl.registrar
    texturl = whoisurl.text

    score = 0
    print(whoisurl)
    print(texturl)
    print(ca_exp) ##verifier la validite
    print(ca_cre) ##verifie le mois? (moins d'un mois)
    print(heb) ##verifie le nom de domaine


resdom("google.fr")
resdom("aclearpath.net")

##feeds.INTHREAT.com/osint
