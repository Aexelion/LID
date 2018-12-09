<Auteur : DUMANGET Dorian>
<Auteur : PEREIRA-REGNAULT Elio>

<Language : Python3>

# TP1 - Cyber Threat Intelligence

## Outil de détection de site d'hameçonnage (Spear-phishing)

Le but de ce TP est de concevoir un outil de détection de site d'hameçonnage. L'outil que nous développerons sera dédié au sites référencés en '.gouv.fr' ainsi les sites en '.org'.

### Principe du spear-phishing

Le spear-phishing est une technique ciblée permettant de récupérer des informations spécifiques d'un ou plusieurs utilisateurs (données bancaires, informations de connexion à un site web ...). Cette méthode passe en général par la création de site web reproduisant, plus ou moins bien, un site connu de la victime.

Ce sont ces différents sites web que l'on cherche à identifier via notre outil.

### Mise en oeuvre

Afin de détecter les sites malveillants, notre analyse sera effectuée de la façon suivante :

-  On vérifie la réputation de l'URL ainsi que l'autorité de certification du site.
-  On vérifie la distance syntaxique par rapport à une liste d'url valide
-  On vérifie ensuite si le site est en HTTPS et bien configuré
-  On demande à l'utilisateur si il souhaite rechercher des informations sur l'hébergeur (Géolocalisation).

## Sources et services utilisés

- Certstream
- This product includes GeoLite2 data created by MaxMind, available from [http://www.maxmind.com](http://www.maxmind.com)
- Python-whois