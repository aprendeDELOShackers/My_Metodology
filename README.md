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

# _Subdomain_
# ======> _Subdomain pasive_
# _Find subdomain in google_
    site:*domain.com -www.domain.com
    {SecurityTrails} https://SecurityTrails.com
    {shodan} https://shodan.io/
    {censys.io} https://censys.io/
    {crt.sh}  https://crt.sh
    {dnsdumpster} https://dnsdumpster.com/
# _Subdomain Scraping_
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

# _Alteration Scaning_
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

# _Enum recursive_
    En palabras simples, nuevamente ejecutamos herramientas como Amass, Subfinder, Assetfinder nuevamente cada uno de los subdominios encontrados.

# _Resolve DNS_
    {puredns} https://github.com/d3mondev/puredns
    puredns resolve permutations.txt -r resolvers.txt
    {shuffledns} 
    shuffledns -d $domino -list $domains/sub/all.txt -o $domains/sub/resol.txt -r $resolvers

# _Https/Http_probe_
    {httprobe}
    {fhc}
    cat $domains/sub/resol_dns/*.txt | fhc | sort -u | anew $domains/httprobe/probe.txt
    {httpx}
    cat $domains/sub/sub-real/subdomain.txt | httpx | sort -u | anew $domains/httprobe/probe.txt
    {urlprobe}
    cat $domains/sub/resol_dns/*.txt | urlprobe | sort -u | anew $domains/httprobe/probe.txt

# _Screenshosts_
    {EyeWitnesst} https://github.com/ChrisTruncer/EyeWitness
    aquatone 
    Escreenshoteer
    gowitness
    {httpscreenshot} https://github.com/breenmachine/httpscreenshot/
    eyeballer
    scrying
    depix
    witnessMet

# _Crawler URL_Antigua & Historial_URL_
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

# _ARCHIVE JS_
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

# _Content_Directory
    {Dirsearch} https://github.com/maurosoria/dirsearch
    # _buscando directorios comunes_
    dirsearch -u http://testasp.vulnweb.com/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o directory.txt
    # _buscando Extensiones comunes_
    dirsearch -u http://testasp.vulnweb.com/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e php.asp -o directory.txt
    {Gobuster} https://github.com/OJ/gobuster
    gobuster dir -u http://testasp.vulnweb.com -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o dir.txt
    gobuster dir -u http://testasp.vulnweb.com/test/ -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o dir.txt
     # _Search extensiones_
    1.1=gobuster dir -u http://localhost:1337/666 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php
    {wfuzz} https://github.com/xmendez/wfuzz
     # _un ejemplo de wfuzz buscando directorios comunes_
    wfuzz -c --hc 404 --hw 388 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://testphp.vulnweb.com/FUZZ
    {ffuf} https://github.com/ffuf/ffuf
     # _buscando directorios comunes_
    ffuf -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -timeuot 100 -u http://testasp.vulnweb.com/FUZZ

# _Port Ananlisis_
    {masscan} https://github.com/robertdavidgraham/masscan
    # _Lo mas basico de usar:_
        masscan 1.0.0.0.1 -p80,8080,443 -oB filename
    # _Analisando para toda una Red_
        masscan 1.0.0.0.1/24 -p1-65535 -oB filename
    # _Escanear varios direcciones IP_
        masscan 1.0.0.0.1,1.0.0.0.2,1.0.0.0.3,1.0.0.0.4 -p80,8080,443 -oB filename
    {dnmasscan} https://github.com/rastating/dnmasscan
        dnmasscan examole.txt dns.log -p1-65535 -oG masscan.log --rate=500
    {RustScan} https://github.com/RustScan/RustScan
    # _Escaneo de puerto individual_
        rustscan -a 0.0.0.1 -p 443
    # _Multiple escaneo de puerto_
        rustscan -a 0.0.0.1 -p 443,80,8080,53
    # _Rango de puerto_
        rustscan -a 0.0.0.1 -p 1-65535
    {naabu} https://github.com/projectdiscovery/naabu
    # _scan simple_ 
        naabu -host hackerone.com
    # _scan de puerto_
        naabu -p 80,443,21-23 -host hackerone.com
        naabu -p1-65535 -host hackerone.com
        naabu -top-ports 100 -host hackerone.com
        naabu -top-ports 1000 -host hackerone.com
    # _sacar puerto_
        naabu -p - -exclude-ports 80,443
    # _lista de Host_
        naabu -list hosts.txt
    # _naabu con una direccion de ASN usando el ASN_
        echo AS14421 | naabu -p 80,443
    # _naabu con salida httpx_
        echo hackerone.com | naabu -silent | httpx -silent
    {nmap} https://nmap.org/
    # _Scanear todos los puertos abierto_
        nmap -p- --open -sS  -T5 -v -n 0.0.0.1
        nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 0.0.0.1
     # _ecaneo potente_
        nmap -sC -sV -p80,443 0.0.0.1

# _Web_Tecnology_
    {wappalyzer} https://www.wappalyzer.com/
    {Builtwith} https://builtwith.com/
    webanalyze
    whatweb
    retire.js
    httpx

# _WAF_Bypass_
    {wafwOOf} https://github.com/EnableSecurity/wafw00f

# _Frameworks_
    {kubebot} https://github.com/anshumanbh/kubebot
    {intrigue} https://github.com/intrigueio/intrigue-core
    {Sn1per} https://github.com/1N3/Sn1per/
    {scantastic-tool} https://github.com/maK-/scantastic-tool/
    {xray} https://github.com/evilsocket/xray
    {datasploit} https://github.com/DataSploit/datasploit
    {inquisitor} https://github.com/penafieljlm/inquisitor
    {spiderfoot} https://github.com/smicallef/spiderfoot

# _Bruteforce_services_
    Brutespray

# _See_all_the_Pages_
    Subtopic

# _Uso_Nuclei_
    # _nuclei nos ayudará a descubrir fallas en un determinado url expuesto_
    # _nuclei -u https://example.com -tags cve -severity critical,high -author geeknik_
    # _Ejecutar nuclei con Hosts valido de la salida "httpx"_
        cat url_valido.txt | nuclei -t /root/nuclei-templates/ -etags sqli.xss,rce -c 50 -o vuln-nuclei.txt
        cat url_valido.txt | nuclei -t /root/nuclei-templates/ -severity low,medium,high,critical -c 50 -o vuln-nuclei.txt
        cat url_valido.txt | nuclei -t /root/nuclei-templates/ -c 50 -o nuclei-tmplates.txt                     
        cat url_valido.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o cves.txt
        cat url_valido.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o vulnerabilities.txt
        cat url_valido.txt | nuclei -t /root/nuclei-templates/technologies/ -c 50 -o technologies.txt
        cat url_valido.txt | nuclei -t /root/nuclei-templates/file/ -c 50 -o file.txt

# _Uso_gf_
    #gf para buscar parametro en la url e inyectar payload
    # _Para ejecutar gf debemos de sacar los hosts de Wayback,gau,gauplus_
        gf xss way_filter.txt | anew xss.txt
        gf sqli way_filter.txt | anew sqli.txt
        gf ssrf way_filter.txt | anew ssrf.txt
        gf idor way_filter.txt | anew idor.txt
        gf lfi way_filter.txt | anew lfi.txt
        gf json-sec way_filter.txt | anew json-sec.txt
    # _Comando avanzado para usar gf con varios tool_
        echo "http://testphp.vulnweb.com" | waybackurls | gf xss

# _Genere_dict
    # _genere_dict (unfurl=paths/parameters) de wayback,gau,gau-plus_
        cat way_filter.txt | unfurl -unique paths > pahts.txt
        cat way_filter.txt | unfurl -unique keys > keys.txt


# _Meg_Uso:Sarch Endpoint_
    # _Obtenga muchas rutas para muchos hosts, sin matar a los hosts_
        {meg} https://github.com/tomnomnom/meg
    # _Ejemplo basico de usar_
        meg --verbose paths hosts
    # _Y guarde la salida en un directorio llamado_
        ./out ====> ejemplo: head -n 20 ./out/example.com/45ed6f717d44385c5e9c539b0ad8dc71771780e0
    # _tambien guardará a un archivo de índice en ./out/index_
    head -n 2 ./out/index
        out/example.com/538565d7ab544bc3bec5b2f0296783aaec25e756 http://example.com/package.json (404 Not Found)
        out/example.com/20bc94a296f17ce7a4e2daa2946d0dc12128b3f1 http://example.com/.well-known/security.txt (404 Not Found)
    # _buscar palabra clave con grep_
        grep -Hnri '< Server:' out/
        out/example.com/61ac5fbb9d3dd054006ae82630b045ba730d8618:14:< Server: ECS (lga/13A2)
        out/example.com/bd8d9f4c470ffa0e6ec8cfa8ba1c51d62289b6dd:16:< Server: ECS (lga/13A3)


############################################################################################################
# _comand_avanzed_
    Provando todos los comando conbinados
    echo "testphp.vulnweb.com" | subfinder -all |  waybackurls | anew history_url.txt && cat history_url.txt | httpx -silent | anew  | unfurl domains | anew | gau-plus | tee anew gau.meg.txt
    meg gau.meg.txt paths


    echo "testphp.vulnweb.com" | subfinder -all |  waybackurls | anew history_url.txt && cat history_url.txt | gf sqli | uro
    echo "testphp.vulnweb.com" | subfinder -all |  waybackurls | anew history_url.txt && cat history_url.txt | gf xss | uro
