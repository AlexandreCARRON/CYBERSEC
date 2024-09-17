#!/bin/bash

# Étape 1 : Découverte des hôtes actifs (en incluant plusieurs types de requêtes : -Ping Scan -ICMP Echo Request -TCP SYN Ping -UDP Ping)
echo "################################################################# Étape 1 : Découverte des hôtes actifs"
nmap -sn -PE -PS -PU <IP:Mask> <IP:Mask> -oN live_hosts.txt
echo "##################### Écriture dans fichier live_hosts.txt"

# Étape 2 : Extraction des adresses IP des hôtes trouvés (uniquement les adresses IP)
echo "################################################################# Étape 2 : Extraction des adresses IP des hôtes trouvés"
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' live_hosts.txt > ip_list.txt
echo "##################### Écriture dans fichier ip_list.txt"

# Vérification si des hôtes ont été découverts
if [ ! -s ip_list.txt ]; then
  echo "Aucun hôte actif trouvé. ARRÊT DU SCRIPT"
  exit 1
fi

# Étape 3 : Scan détaillé de tous les ports des hôtes actifs
# Le scan SYN (-sS) est effectué sur tous les ports (-p-) et détermine les versions des services (-sV)
echo "################################################################# Étape 3 : Scan détaillé de tous les ports des hôtes actifs"
nmap -iL ip_list.txt -p- -sS -sV -oA detailed_scan
echo "##################### Écriture dans fichier detailed_scan"

# Étape 4 : Extraction des hôtes qui hébergent des services web (ports HTTP ou HTTPS ou autres)
echo "################################################################# Étape 4 : Extraction des hôtes qui hébergent des services web"

# On ressort uniquement l'IP des hôtes qui ont des ports HTTP ou HTTPS ouverts
grep -E 'open.*http*' detailed_scan.gnmap | awk '{print $2}' > web_hosts.txt
echo "##################### Écriture d'un fichier web_hosts.txt"

# Vérification si des hôtes web ont été découverts
if [ -s web_hosts.txt ]; then
  echo "Quelques hôtes web ont été trouvés et listés dans web_hosts.txt et web_hosts_with_port.txt"
else
  echo "Aucun hôte web trouvé."
fi

# On ressort IP:PORT de tous les sites web identifiés
awk '/Nmap scan report/{ip=$NF} /open.*http*/{print ip ":" $1}' detailed_scan.nmap | sed 's:/.*::' | sed 's/(\([0-9.]*\))/\1/g' > web_hosts_with_port.txt
echo "##################### Écriture d'un fichier web_hosts_with_port.txt"

# On ressort les IP et port avec les produits, versions et OS
# /!\ ATTENTION NE FONCTIONNE PLUS /!\ 
grep -E "open.*" detailed_scan.nmap | awk '
/Nmap scan report for/ {
    ip = $5
}
/open/ {
    port = $1
    service = $3
    product = $4
    version = $5
    os = $6
    printf "%s:%s => %s %s %s OS %s \n", ip, port, service, product, version, os
}
' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+' > web_hosts_with_product_version.txt
echo "##################### Écriture d'un fichier web_hosts_with_product_version.txt"

# Etape 5 : Scan des IP:PORT qui ont des services web exposés dans le but de trouver de nouvelles failles
#  /!\ ATTENTION /!\ REGLER SOUS ETAPE PRECEDENTE ! /!\
sudo nikto -h web_hosts_with_port.txt > resultats_NIKTO_web_hosts_with_port.txt
echo "################################################################# Etape 5 : écriture du fichier nikto_web_hosts.txt"

# Étape 6 : Génération du fichier XML à partir du scan détaillé (en incluant le scan complet des services)
echo "################################################################# Étape 6 : Génération du fichier XML"
nmap -iL ip_list.txt -A -oX output.xml
# commande avec le meilleur taux de découverte d'équipements : nmap -n -sn -PE -PP -PS -PA -T4 --source-port 53 <IP:Mask>  , a vérifier : Les infos ressorties sont elles aussi complètes que commande ci dessus
echo "##################### Écriture d'un fichier output.xml"

# Étape 7 : Conversion du fichier XML en HTML pour visualisation
echo "################################################################# Étape 7 : Conversion du fichier XML en HTML pour visualisation"
xsltproc /usr/share/nmap/nmap.xsl output.xml -o output.html
echo "##################### Vous pouvez maintenant ouvrir le fichier output.html dans un navigateur pour visualiser les résultats du dernier scan"
