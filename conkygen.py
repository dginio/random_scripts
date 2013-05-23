#!/usr/bin/python
#coding:utf-8

# Generateur conky reseau dynamique - Antoine BOTTE
import os,sys,urllib2
from scapy.all import *

if "0" in open("/home/dginio/scripts/exec_test","r").read() :
	open("/home/dginio/scripts/exec_test","w").write("1")

	conf.verb = 0

	# Variables de fichiers utiles
	pathscript = "/home/dginio/scripts/"
	file_netinfo = pathscript+"netinfo.txt"
	file_conky = pathscript+"conkyrc"
	file_conkygen = pathscript+"conkygen.sh"
	# configuration proxy pour scapy
	# proxies = {'http': 'http://x.x.x.x:x'}

	# Fonction d'execution de commande bash avec resultat en return
	def execute(cmd): return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

	# Recupère la résoultion actuelle
	resolution = execute("echo $(xrandr | grep '\*\+' | egrep -o '[0-9]+x[0-9]+' )")
	x = int(resolution.split("x")[0])
	y = int(resolution.split("x")[1])

	# Fonction de conversion d'un masque de sous réseau en bits => string
	values=[128,64,32,16,8,4,2,1]
	def netmaskToBits(mask):
		byte=0
		for i in mask.split('.'):
			i = int(i)
			for value in values:
				if i >= value: byte += 1; i-= value
		return str(byte)
	write = 0
	if len(sys.argv) > 1 and sys.argv[1] == "write":
		write = 1

	connect = 0
	try :
		# Passerelle récupérée dans la liste des routes de scapy
		gw = [e[2] for e in conf.route.routes if e[2]!='0.0.0.0'][0]
		connect = 1
		if "Not Connected" in open(file_netinfo,'r').read():
			write = 1
	except :
		connect = 0
	
	if connect :
		# Récupérer l'ip public
		try :
			request = urllib2.Request("http://www.dginio.free.fr/ip")
			ip_pub = urllib2.urlopen(request).read()
		except :
			print "|"
			ip_pub = "---"
	
		# Récupération de la table ARP
		arp = execute("arp -an")
	
		# Etat de l'association avec l'adresse MAC de la passerelle ( fixe ou dynamique )
		if "PERM" in arp: gwState = "Static"
		else: gwState = "Dynamic"
	
		# Adresse mac de la passerelle depuis la table arp
		gwMac = re.compile(gw+'\) à (.*) \[').findall(arp)[0]
	
		# Adresse MAC de la passerelle attribué en cas de requete ARP ( detection MTIM )
		gwMacDyn = getmacbyip(gw)
	
		# Comparaison des adresse MAC pour détection MITM
		if gwMac == gwMacDyn: mitm = "OK"
		else: mitm = "${color3}MITM"
	
		net_iface = conf.iface
	
		# Ifconfig sur l'interface utilisée dans scapy
		ifconfig = execute("ifconfig "+conf.iface)
	
		# Masque de sous réseau récupéré dans ifconfig
		mask = re.compile('Masque:(.*)').findall(ifconfig)[0]
	
		# Masque de sous réseau pour le format cidr
		maskCidr = netmaskToBits(mask)
	
		# Adresse IP de l'interface récupéré dans ifconfig
		addr = re.compile('inet adr:(.*) B').findall(ifconfig)[0][:-1]
	
		# Adresse mac de l'interface récupéré dans ifconfig
		mac = re.compile('HWaddr (.*)').findall(ifconfig)[0]
	
		# Récupération de l'adresse du serveur DHCP (dans /var/lib/dhcp/dhclient.leases)
		# Booléen permettant de définir si l'interface est passé dans la lecture du fichier lease DCHP
		findIface = 0
		for line in re.compile('.*').findall(open('/var/lib/dhcp/dhclient.leases','r').read()):
			if conf.iface in line: findIface = 1
			if findIface and "option dhcp-server-identifier" in line:
				dhcp = re.compile('option dhcp-server-identifier (.*)').findall(line)[0][:-1]
				findIface = 0
	
		# Adresse(s) IP de(s) serveur(s) DNS récupéré(s) dans le fichier /etc/resolv.conf
		dns = ", ".join(re.compile('nameserver (.*)').findall(open('/etc/resolv.conf','r').read()))
	
		# Récupération des informations sur le proxy depuis le fichier de conf perso
		proxy = open("/home/dginio/scripts/proxy/proxy.conf","r").read().split(" ")
	
		# Adresse:port du proxy
		proxyPath = proxy[0].strip()

		# Etat du proxy
		if int(proxy[1].strip()) == 1: proxyState = "On"
		else : proxyState = "Off"

		# arping sur le réseau local avec scapy ajouté dans le fichier ips.txt
		fips = open(pathscript+"ips.txt","w")
		for ip in [t[1].psrc for t in arping(gw+"/"+maskCidr)[0][ARP]]: fips.write(ip+"\n")
		fips.close()
	
		# Trie par IP le fichier ips.txt et supprime les doublons d'adresses
		os.system("cat "+pathscript+"ips.txt |sort -n -t . -k 3,3n -k 4,4n |uniq > "+pathscript+"tmp ; mv "+pathscript+"tmp "+pathscript+"ips.txt")
	
		# Lecture du fichier ips.txt
		fips = open(pathscript+"ips.txt","r").readlines()
	
		# Adresses placées dans un tableau sans les \n
		ips = []
		for ip in fips: ips.append(ip.strip())
	
		# Envoi d'une requete ICMP à chaque entrées du tableau
		ans,unans=sr(IP(dst=ips)/ICMP(),timeout=1)
	
		# Récupération des réponses dans un dictionnaires reply avec les ttl
		reply = [(p[1].src,p[1].ttl) for p in ans[IP]]
	
		# Suppression des adresses IP qui n'ont pas répondu au ping en passant dans un fichier tmp
		# fichier tmp remplacer par ips.txt ensuite pour conserver les ip actives
		noreply = []
		tmp = open(pathscript+"tmp","w")
		for line in fips:
			test = 0
			for ip in [p.dst for p in unans[IP]]:	
				if ip in line: test = 1
			if test == 1: noreply.append(ip)
			else: tmp.write(line)
		tmp.close()
		os.system("mv "+pathscript+"tmp "+pathscript+"ips.txt")
		net = conf.iface+"&"+addr+"/"+maskCidr+"&"+mac+"&"+gw+" - "+gwState+" - "+mitm+"&"
		if mitm == "OK": net += gwMac+"&"
		else: gwMac+" | "+gwMacDyn+"&"
		net += dhcp+"&"+dns+"&"+proxyPath+" - "+proxyState+"&"+ip_pub+"&"+" "*60+"Online : "+str(len(reply))+" - Offline : "+str(len(noreply))+"&"
		for ip,ttl in reply : net += " "*60+"   [+]  "+ip+" "*(17-len(ip))+str(ttl)+"\n"
		for ip in noreply : net += " "*60+"   [-]  "+ip+" "*(17-len(ip))+"?\n"
	
	else :
		net = "Not connected ?"+"&"*8

	tmp = open(pathscript+"tmp","w")
	tmp.write(net)
	tmp.close()
	os.system("mv "+pathscript+"tmp "+file_netinfo)

	if write == 1:
		# Déclaration variables conky
		goto = "100"
		bar = "270"
		refresh = "20"
		t = ["SYSTEM","TOP","NETWORK","PUBLIC","HOSTS"]
		def title(n) : return "${voffset 7}${font DroidSans:bold:size=8.25}${color3}"+t[n]+"${offset 8}${color0}${voffset -1}${cpubar cpu0 1,"+str(374-len(t[n]*5))+"}"

		nb_proc = int(execute("cat /proc/cpuinfo | grep processor | wc -l"))
		cpu = []
		for i in range(4):
			if i < nb_proc : cpu.append("${color1}CP"+str(i)+" :$color0 ${cpu cpu"+str(i)+"}% ${goto "+goto+"}$color3${cpubar cpu"+str(i)+" 6,"+bar+"}\n")
			else : cpu.append("${color1}CP"+str(i)+" :$color0 none\n")

		# Réécriture du fichier conkyrc
		conky = open(file_conky,'w')
		conky.writelines([
		"own_window yes\n",
		"own_window_transparent yes\n",
		"own_window_type desktop\n",
		"own_window_hints undecorated,below,sticky,skip_taskbar\n",
		"own_window_argb_visual yes\n",
		"own_window_argb_value 100\n",
		"use_xft yes\n",
		"font Droid Sans Mono-10\n",
		"uppercase no\n",
		"update_interval 1\n",
		"total_run_times 0\n",
		"double_buffer yes\n",
		"default_color white\n",
		"default_shade_color black\n",
		"default_outline_color black\n",
		"color0 FFFFFF\n",
		"color1 FFB515\n",
		"color2 000000\n",
		"color3 D70303\n",
		"border_width 0\n",
		"draw_shades yes\n",
		"draw_outline no\n",
		"draw_graph_borders no\n",
		"no_buffers yes\n",
		"cpu_avg_samples 2\n",
		"alignment top_left\n",
		"gap_y 0\n",
		"text_buffer_size 4096\n",
		"TEXT\n\n",
		title(0)+"${font}\n",
		"${color1}$nodename$color0 $kernel\n",
		"${color1}Uptime :$color0 $uptime\n",
		"${color1}Remaining : $color0${texeci "+refresh+" acpi | sed 's/Battery 0: //' | sed 's/, [0-9]\+%,//' | grep -o '[a-Z]\+\ [0-9]\{2\}:[0-9]\{2\}'}\n",
		"${color1}BAT :$color0 ${battery_percent BAT0}% ${goto "+goto+"}$color3${battery_bar 6,"+bar+" BAT0}\n",
		"${color1}SSD :$color0 ${fs_used_perc /}% ${goto "+goto+"}$color3${fs_bar 6,"+bar+" /} \n",
		"${color1}Mem :$color0 $memperc% ${goto "+goto+"}$color3${membar 6,"+bar+"} \n",
		cpu[0],
		cpu[1],
		cpu[2],
		cpu[3],
		title(1)+"${font}\n",
		"${color1}Processes : ${color0}$processes\n",
		"${color1}Name              PID    CPU%   MEM%\n",
		"${color1}${top name 1} ${color0}${top pid 1} ${top cpu 1} ${top mem 1}\n",
		"${color1}${top name 2} ${color0}${top pid 2} ${top cpu 2} ${top mem 2}\n",
		"${color1}${top name 3} ${color0}${top pid 3} ${top cpu 3} ${top mem 3}\n",
		"${color1}${top name 4} ${color0}${top pid 4} ${top cpu 4} ${top mem 4}\n",
		"${color1}${top name 5} ${color0}${top pid 5} ${top cpu 5} ${top mem 5}\n",
		"${color1}${top name 6} ${color0}${top pid 6} ${top cpu 6} ${top mem 6}\n",
		"${color1}${top name 7} ${color0}${top pid 7} ${top cpu 7} ${top mem 7}\n",
		"${color1}${top name 8} ${color0}${top pid 8} ${top cpu 8} ${top mem 8}\n",
		"${color1}${top name 9} ${color0}${top pid 9} ${top cpu 9} ${top mem 9}\n",
		"${color1}${top name 10} ${color0}${top pid 10} ${top cpu 10} ${top mem 10}\n",
		title(2)+"${font}\n",
		"${color1}iface : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f1 }\n",
		"${color1}IP  : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f2 }\n",
		"${color1}MAC : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f3 }\n",
		"${color1}Gateway : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f4 }\n",
		"${color1}MAC : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f5 }\n",
		"${color1}DHCP server : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f6 }\n",
		"${color1}DNS server(s) : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f7 }\n",
		"${color1}Proxy : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f8 }\n",
		"${color1}Downloaded : ${color0}${totaldown "+net_iface+"}\n",
		"${color1}Uploaded   : ${color0}${totalup "+net_iface+"}\n",
		"${color1}Download ${color0}${downspeed "+net_iface+"}\n",
		"${color2}${downspeedgraph "+net_iface+" 25, 330 FFB515 D70303 -t}\n",
		"${color1}Upload ${color0}${upspeed "+net_iface+"}\n",
		"${color2}${upspeedgraph "+net_iface+" 25, 330 FFB515 D70303 -t}\n",
		title(3)+"${font}\n",
		"${color1}${font :pixelsize=34} ${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f9 }${font}\n",
		"${offset 398}${voffset -800}"+title(4)+"${font}\n",
		"${color1}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f10 }\n",
		"${color0}${texeci "+refresh+" cat "+file_netinfo+" | cut -d'&' -f11 }\n",
		"${texeci 60 sudo bash "+file_conkygen+"}\n"
		])
		conky.close()

	if not (execute("ps aux | grep 'conky -c' | grep -v grep")): execute("conky -c /home/dginio/scripts/conkyrc > /dev/null 2>&1")
	open("/home/dginio/scripts/exec_test","w").write("0")
