<Auteur : DUMANGET Dorian>
<Auteur : PEREIRA-REGNAULT Elio>

# TP1 - Cyber Threat Intelligence

## Outil de détection de site d'hameçonnage (Spear-phishing)

Le but de ce TP est de concevoir un outil de détection de site d'hameçonnage. L'outil que nous développerons sera dédié au sites référencés en '.gouv.fr' ainsi les sites en '.org'.

### Principe du spear-phishing

Le spear-phishing est une technique ciblée permettant de récupérer des informations spécifiques d'un ou plusieurs utilisateurs (données bancaires, informations de connexion à un site web ...). Cette méthode passe en général par la création de site web reproduisant, plus ou moins bien, un site connu de la victime.

Ce sont ces différents sites web que l'on cherche à identifier via notre outil.

### Mise en oeuvre

Afin de détecter les sites malveillants, notre analyse sera effectuée en 2 parties :

-  Première partie

     - On vérifie la réputation de l'adresse IP, du système autonome ainsi que l'autorité de certification du site.
     -  On recherche des informations sur l'hébergeur (Géolocalisation, traffic estimé).
     -  On vérifie la distance syntaxique par rapport à une liste d'url valide
     -  On vérifie ensuite si le site est en HTTPS et bien configuré

-  Deuxième partie

  - Analyse du JS dans la page
  - Analyse des redirections
  - Présence de formulaire à données sensibles
  - RGPD (Sites EU)

En cas d'ambiguïté des résultats après analyse, on redonne la main à l'utilisateur pour vérifier le site en question.

L'outil sera développer en python3.

## Sources et services utilisés

- Certstream
- GeoIP2 Downloadable Databases
- Python-whois