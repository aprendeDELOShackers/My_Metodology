# _Josema_Metodology_
os presento como me organizo en la parte de reconocimiento de un objetivo en el mundo de "Bug Bounty"

# _Metodology For Bug Hunter's_

#TIMe_Metodology

# _Recon_
    Scope domain(HackerOne or Budcrowd)
    ejemplo.com
    * ejemplo.com
    2_Pre-Recon

# _Acquisitions(web)_
    {crunchbase} https://www.crunchbase.com/
    {whoisxmlapi} https://www.whoisxmlapi.com/
    {whoxy} https://www.whoxy.com/
# _ASN enumerations source_
    {bgp.he.net} https://bgp.he.net/
# _ASN enumerations  CMD_LINE para encontrar ASN_
    {amass} https://github.com/caffix/amass
        amass intel -org {dominio} | awk -F, '{print $1}' | anew asn.txt | for i in $(cat asn.txt);do amass intel -asn $i;done
# _ASN enumerations  CMD_LINE. Para buscar rango de IP desde un ASN Encontrado_
    {whois} 
        whois -h whois.radb.net  -- '-i origin AS714' | grep -Eo "([0-9.]+){4}/[0-9]+" | anew rango_ip.txt
    {metabigor} https://github.com/j3ssie/metabigor
        echo "tesla" | metabigor net --org -o /tmp/result.txt
    {Asnlookup} https://github.com/yassineaboukir/Asnlookup
        python asnlookup.py -o testla
# _Buscar Dominio o Host activo  por rango de IP (IP/rango)_
    {prips} https://github.com/honzahommer/prips.sh
        prips ip/range | hakrevdns |  awk '{print $2}'  |  anew domain.txt 
    {amass} https://github.com/caffix/amass =====> Para buscar dominio por ASN
        amass intel --asn 914 | enew domain.txt
    {mapcidr} https://github.com/projectdiscovery/mapcidr
        echo ip/range | mapcidr -silent | dnsx -ptr -resp-only -o output.txt

3_Roots
# _Enumertions domain name (Reverse Whois)_
    {Reverse WHOIS} (https://Whoxy.com/)
    company or name organization & email
    {Reverse WHOIS} (https://www.reversewhois.io/)
# _Encuentre todos los nombres de dominio propiedad de una persona o empresa._
    {Reverse WHOIS} (https://github.com/vysecurity/DomLink) CMD_LINE
        python domLink.py -D target.com -o target.out.txt
# _Ad/Analytics (https://builtwith.com/relationships/)_
    Google Fu
    google 
    Copyright text
    Terms of Services
    Privacy Policy

# _google_Dorks_
    {Goohak} https://github.com/1N3/Goohak/
    {GoogD0rker} https://github.com/ZephrFish/GoogD0rker/
# _Github_Dorks_
    {gist jhadixx} https://gist.github.com/jhaddix/2a08178b94e2fb37ca2bb47b25bcaed1
    {github search} https://github.com/search
    {gitrob} https://github.com/michenriksen/gitrob
    {git-all-secrets} https://github.com/anshumanbh/git-all-secrets
    {git-secrets} https://github.com/awslabs/git-secrets
    {repo-supervisor} https://github.com/auth0/repo-supervisor
# _s3
    {sandcastle} https://github.com/yasinS/sandcastle
    {bucket_finder} https://digi.ninja/projects/bucket_finder.php

# _Subdomain
# _======> subdomain pasive
Find subdomain in google
    site:*domain.com -www.domain.com
    {SecurityTrails} https://SecurityTrails.com
    {shodan} https://shodan.io/
    {censys.io} https://censys.io/
    {crt.sh}  https://crt.sh
    {dnsdumpster} https://dnsdumpster.com/
# _Subdomain Scraping
    {sublister} 
    sublist3r -d $dominio -o sublis.txt
    {amass} https://github.com/caffix/amass
    amass enum -d $dominio | sort -u | anew amass.txt
    {subfinder} https://github.com/projectdiscovery/subfinder
    subfinder -d $dominio | sort -u | anew subfin.txt
    {github subdomains.py} https://github.com/gwen001/github-search/blob/master/github-subdomains.py
    github-subdomains.py -t (token) -d $dominio | sort -u | anew git_su.txt
    {assetfinder} https://github.com/tomnomnom/assetfinder
    assetfinder --subs-only $dominio | sort -u | anew sub/asset.txt
    {findomain} https://github.com/Findomain/Findomain
    findomain -t $dominio  -o sub.txt
    {turbolist3r.py} https://github.com/aboul3la/sublist3r
    turbolist3r.py -d $dominio -o turbo.txt
    {subdomainizer} https://github.com/nsonaniya2010/SubDomainizer.git
    python3 SubDomainizer.py -u http://www.vulnweb.com -o sub.txt
    {anubis} https://github.com/jonluca/Anubis
    anubis -t $dominio  -S  -o anub.txt
    {acamar.py} https://github.com/si9int/Acamar/blob/master/acamar.py
    acamar.py $dominio 2> /dev/null | grep $dominio | sort -u | anew $dominio/sub/acam.txt
    {ctfr.p} https://github.com/UnaPibaGeek/ctfr.git  ===> Certificado SSL/TLS
    ctfr.py -d $dominio -o subdomain.txt
    {crobat} https://github.com/Cgboal/SonarSearch
    crobat -s $dominio | sort -u | anew subdomain.txt

# _Subdomain BruteForce_
    {amass} https://github.com/OWASP/Amass
    amass enum -brute -d example.com
    {shuffledns} https://github.com/projectdiscovery/shuffledns
    shuffledns -d $dominio -w $wordlists -r $resolvers | sort -u | anew $dominio/sub/shuff.txt
    {puredns} https://github.com/d3mondev/puredns
    puredns bruteforce $wordlists $dominio -r $resolvers | tee $dominio/sub/pure.txt
    {dnscan} https://github.com/rbsec/dnscan 
    dnscan.py -d hackerone.com -w /usr/share/wordlists/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt
     -L /home/josema96/HackerOne/hunters_tools/resolvers.txt
    Used for DNS subdomain bruteforcing
    gobuster dns -d example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

# _Spider the seeds =====> araña las semillas ====== Web crawling subdomain_
    {GoSpider}
    cat subdomain.txt | subfinder -d vulnweb.com | fhc | sed '/^.\{2048\}./d' |  grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep 'vulnweb.com' | sort -u | anew gospiderSub.txt
    {waymore} https://github.com/xnl-h4ck3r/waymore
    python3 waymore.py -i domain.com -mode U | unfurl domains | anew sundomain.txt
    {waybackurls} https://github.com/tomnomnom/waybackurls
    echo "domain.com" | waybackurls | unfurl domains | anew subdomain.txt
    cat subdomain.txt | waybackurls | unfurl domains | anew subdomain.txt
    {gau}
    echo "domain.com" | gau | unfurl domains | anew subdomain.txt
    cat subdomain.txt | gau | unfurl domains | anew subdomain.txt
    {gauplus}
    echo "domain.com" | gauplus -subs | unfurl domains | anew subdomain.txt
    cat subdomain.txt | gauplus -subs | unfurl domains | anew subdomain.txt
Alteration Scaning
{altdns} https://github.com/infosec-au/altdns
altdns -i subdomain.txt -o data_output -w worl.txt -r -s results_output.txt
{dnsgen}  https://github.com/ProjectAnte/dnsgen
echo "vulnweb.com" | dnsgen - | tee posi_sub.txt
echo "vulnweb.com" | subfinder -silent | dnsgen - | massdns -r /path/to/resolvers.txt -t A -o J --flush 2>/dev/null | wc -l
{gotator} https://github.com/Josue87/gotator
gotator -sub sub.txt -perm permutations.txtt -depth 1 -numbers 10 -mindup -adv -md | tee gotator_permu/perm.txt
{dmut} https://github.com/bp0lr/dmut
dmut -u testphp.vulnweb.com -d permutations.txtt -w 100 --dns-timeout 300 --dns-retries 5 --dns-errorLimit 25 --show-stats -o results.txt
cat sub.txt | dmut -d permutations.txtt -w 100 --dns-timeout 300 --dns-retries 5 --dns-errorLimit 25 --show-stats -o results.txt  
{dnsfaster}  https://github.com/bp0lr/dnsfaster
dnsfaster --domain example.com --in "dnslist.txt" --out "resolvers.txt" --tests 1000 --workers 50 --filter-time 400 --filter-errors 50 --filter-rate 90 --save-dns
8_Enum recursive
En palabras simples, nuevamente ejecutamos herramientas como Amass, Subfinder, Assetfinder nuevamente cada uno de los subdominios encontrados.
9_Resolve DNS
{puredns} https://github.com/d3mondev/puredns
puredns resolve permutations.txt -r resolvers.txt
{shuffledns} 
shuffledns -d $domino -list $domains/sub/all.txt -o $domains/sub/resol.txt -r $resolvers
10_Https_probe
{httprobe}
{fhc}
cat $domains/sub/resol_dns/*.txt | fhc | sort -u | anew $domains/httprobe/probe.txt
{httpx}
cat $domains/sub/sub-real/subdomain.txt | httpx | sort -u | anew $domains/httprobe/probe.txt
{urlprobe}
cat $domains/sub/resol_dns/*.txt | urlprobe | sort -u | anew $domains/httprobe/probe.txt
11_Screenshosts
{EyeWitnesst} https://github.com/ChrisTruncer/EyeWitness
aquatone 
Escreenshoteer
gowitness
{httpscreenshot} https://github.com/breenmachine/httpscreenshot/
eyeballer
scrying
depix
witnessMet
12_Crawler URL_Antigua & Historial_URL
{Wayback Machine} https://web.archive.org/
{Waybackrobots} https://gist.github.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07
{Google (con el filtro de tiempo activado)} https://google.com/
{waybackurls} https://github.com/tomnomnom/waybackurls
echo "domain.com" | waybackurls | anew history_url.txt
cat subdomain.txt | waybackurls | anew history_url.txt
{gau} https://github.com/lc/gau
echo "domain.com" | gau |  anew history_url.txt
cat subdomain.txt | gau |  anew history_url.txt
{gauplus} https://github.com/bp0lr/gauplus
echo "domain.com" | gauplus -t 5 -random-agent -subs |  anew history_url.txt
cat subdomain.txt | gauplus -t 5 -random-agent -subs | anew history_url.txt
{waymore}
python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt
{LinkFinder} https://github.com/GerbenJavado/LinkFinder
{GoLinkFinder} https://github.com/0xsha/GoLinkFinder
{linksDumper}
ARCHIVE JS
{getJS} https://github.com/003random/getJS
cat domains.txt | getJS --output results.txt 
getJS --url https://poc-server.com --output results.txt
{JSScanner} https://github.com/0x240x23elu/JSScanner.git
python3 JSScanner.py   ========> Ingrese cualquier archivo: text.txt (su archivo de enlaces)
{LinkFinder} https://github.com/GerbenJavado/LinkFinder 
python3 linkfinder.py -i https://example.com -d
{SecretFinder } https://github.com/m4ll0k/SecretFinder
python3 SecretFinder.py -i https://example.com/ -e
{subjs}
cat urls.txt | subjs 
subjs -i urls.txt
cat hosts.txt | gau | subjs
{BurpJSLinFinder} https://github.com/InitRoot/BurpJSLinkFinder
13_Content_Directory
{Dirsearch} https://github.com/maurosoria/dirsearch
buscando directorios comunes:
dirsearch -u http://testasp.vulnweb.com/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o directory.txt
buscando Extensiones comunes:
dirsearch -u http://testasp.vulnweb.com/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e php.asp -o directory.txt
{Gobuster} https://github.com/OJ/gobuster
gobuster dir -u http://testasp.vulnweb.com -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o dir.txt
gobuster dir -u http://testasp.vulnweb.com/test/ -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o dir.txt
 #Search extensiones
1.1=gobuster dir -u http://localhost:1337/666 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php
{wfuzz} https://github.com/xmendez/wfuzz
un ejemplo de wfuzz buscando directorios comunes:
wfuzz -c --hc 404 --hw 388 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://testphp.vulnweb.com/FUZZ
{ffuf} https://github.com/ffuf/ffuf
buscando directorios comunes:
ffuf -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -timeuot 100 -u http://testasp.vulnweb.com/FUZZ
14_Port Ananlisis
{masscan} https://github.com/robertdavidgraham/masscan
Lo mas basico de usar:
masscan 1.0.0.0.1 -p80,8080,443 -oB filename
Analisando para toda una Red
masscan 1.0.0.0.1/24 -p1-65535 -oB filename
Escanear varios direcciones IP
masscan 1.0.0.0.1,1.0.0.0.2,1.0.0.0.3,1.0.0.0.4 -p80,8080,443 -oB filename
{dnmasscan} https://github.com/rastating/dnmasscan
dnmasscan examole.txt dns.log -p1-65535 -oG masscan.log --rate=500
{RustScan} https://github.com/RustScan/RustScan
Escaneo de puerto individual
rustscan -a 0.0.0.1 -p 443
Multiple escaneo de puerto
rustscan -a 0.0.0.1 -p 443,80,8080,53
Rango de puerto
rustscan -a 0.0.0.1 -p 1-65535
{naabu} https://github.com/projectdiscovery/naabu
scan simple 
naabu -host hackerone.com
scan de puerto
naabu -p 80,443,21-23 -host hackerone.com
naabu -p1-65535 -host hackerone.com
naabu -top-ports 100 -host hackerone.com
naabu -top-ports 1000 -host hackerone.com
sacar puerto
naabu -p - -exclude-ports 80,443
lista de Host
naabu -list hosts.txt
naabu con una direccion de ASN usando el AS
echo AS14421 | naabu -p 80,443
naabu con salida httpx
echo hackerone.com | naabu -silent | httpx -silent
{nmap} https://nmap.org/
Scanear todos los puertos abierto
nmap -p- --open -sS  -T5 -v -n 0.0.0.1
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 0.0.0.1
 ecaneo potente
nmap -sC -sV -p80,443 0.0.0.1
15_Web_Tecnology
{wappalyzer} https://www.wappalyzer.com/
{Builtwith} https://builtwith.com/
webanalyze
whatweb
retire.js
httpx
16_WAF_Bypass
{wafwOOf} https://github.com/EnableSecurity/wafw00f
17_Frameworks
{kubebot} https://github.com/anshumanbh/kubebot
{intrigue} https://github.com/intrigueio/intrigue-core
{Sn1per} https://github.com/1N3/Sn1per/
{scantastic-tool} https://github.com/maK-/scantastic-tool/
{xray} https://github.com/evilsocket/xray
{datasploit} https://github.com/DataSploit/datasploit
{inquisitor} https://github.com/penafieljlm/inquisitor
{spiderfoot} https://github.com/smicallef/spiderfoot
18_Bruteforce_services
Brutespray
19_See_all_the_Pages
Subtopic

20_Uso_Nuclei
#nuclei nos ayudará a descubrir fallas en un determinado url expuesto
nuclei -u https://example.com -tags cve -severity critical,high -author geeknik
Ejecutar nuclei con Hosts valido de la salida "httpx"
cat url_valido.txt | nuclei -t /root/nuclei-templates/ -etags sqli.xss,rce -c 50 -o vuln-nuclei.txt
cat url_valido.txt | nuclei -t /root/nuclei-templates/ -severity low,medium,high,critical -c 50 -o vuln-nuclei.txt
cat url_valido.txt | nuclei -t /root/nuclei-templates/ -c 50 -o nuclei-tmplates.txt                     
cat url_valido.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o cves.txt
cat url_valido.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o vulnerabilities.txt
cat url_valido.txt | nuclei -t /root/nuclei-templates/technologies/ -c 50 -o technologies.txt
cat url_valido.txt | nuclei -t /root/nuclei-templates/file/ -c 50 -o file.txt

21_Uso_gf
#gf para buscar parametro en la url e inyectar payload
Para ejecutar gf debemos de sacar los hosts de Wayback,gau,gauplus
gf xss way_filter.txt | anew xss.txt
gf sqli way_filter.txt | anew sqli.txt
gf ssrf way_filter.txt | anew ssrf.txt
gf idor way_filter.txt | anew idor.txt
gf lfi way_filter.txt | anew lfi.txt
gf json-sec way_filter.txt | anew json-sec.txt
Comando avanzado para usar gf con varios tool
echo "http://testphp.vulnweb.com" | waybackurls | gf xss

22_Genere_dict
#genere_dict (unfurl=paths/parameters) de wayback,gau,gau-plus
cat way_filter.txt | unfurl -unique paths > pahts.txt
cat way_filter.txt | unfurl -unique keys > keys.txt


23_Meg_Uso:Sarch Endpoint
#Obtenga muchas rutas para muchos hosts, sin matar a los hosts
{meg} https://github.com/tomnomnom/meg
Ejemplo basico de usar
meg --verbose paths hosts
Y guarde la salida en un directorio llamado
./out ====> ejemplo: head -n 20 ./out/example.com/45ed6f717d44385c5e9c539b0ad8dc71771780e0
tambien guardará a un archivo de índice en ./out/index:
head -n 2 ./out/index
out/example.com/538565d7ab544bc3bec5b2f0296783aaec25e756 http://example.com/package.json (404 Not Found)
out/example.com/20bc94a296f17ce7a4e2daa2946d0dc12128b3f1 http://example.com/.well-known/security.txt (404 Not Found)
buscar palabra clave con grep
grep -Hnri '< Server:' out/
out/example.com/61ac5fbb9d3dd054006ae82630b045ba730d8618:14:< Server: ECS (lga/13A2)
out/example.com/bd8d9f4c470ffa0e6ec8cfa8ba1c51d62289b6dd:16:< Server: ECS (lga/13A3)



24_comand_avanzed
Provando todos los comando conbinados
echo "testphp.vulnweb.com" | subfinder -all |  waybackurls | anew history_url.txt && cat history_url.txt | httpx -silent | anew  | unfurl domains | anew | gau-plus | tee anew gau.meg.txt
meg gau.meg.txt paths


echo "testphp.vulnweb.com" | subfinder -all |  waybackurls | anew history_url.txt && cat history_url.txt | gf sqli | uro
echo "testphp.vulnweb.com" | subfinder -all |  waybackurls | anew history_url.txt && cat history_url.txt | gf xss | uro
