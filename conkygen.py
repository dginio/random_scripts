#!/usr/bin/python
#coding:utf-8

# --- Dginio --- 

# You need screen, scapy, conky
# The conkyrc file is written for a screen resolution of 1600*900

# conkyrc generator, dynamic network informations
import os,sys,urllib2
from scapy.all import *

conf.verb = 0

# Execute sh command and return the result
def execute(cmd): return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

# vars
pathscript = "/home/user/scripts/conky/"
current_filename = os.path.basename(__file__)
file_proxy = pathscript+"../proxy/proxy.conf"
file_netinfo = pathscript+"netinfo.txt"
file_conky = pathscript+"conkyrc"

# Uptade network informations every auto_refresh+10 seconds
auto_refresh = "50"

# Check if this process is not already running
if int(execute("ps aux | grep '"+current_filename+"' | grep -v 'grep' | wc -l").strip()) < 4 :
	
	# Get proxy informations from the proxyconf file
	proxy = open(file_proxy,"r").read().split(" ")
	
	# proxy conf ( ip:port )
	proxyPath = proxy[0].strip()

	# state
	if int(proxy[1].strip()) == 1 :
		proxyState = "On"
		proxies = {'http': 'http://'+proxyPath}
	else : proxyState = "Off"
	
	# Convert netmask in bits ( return a string )
	values=[128,64,32,16,8,4,2,1]
	def netmaskToBits(mask):
		byte=0
		for i in mask.split('.'):
			i = int(i)
			for value in values:
				if i >= value: byte += 1; i-= value
		return str(byte)
	
	# 'write' means the conkyrc file must be rewrite
	write = 0
	if len(sys.argv) > 1 and sys.argv[1] == "write":
		write = 1
	
	# Check if the connection is up
	connect = 0
	open_netinfo = open(file_netinfo,"r")
	netinfo_content = open_netinfo.read()

	try :
		# Get the gateway in scapy informations, if it works, we are connected
		gw = [e[2] for e in conf.route.routes if e[2]!='0.0.0.0'][0]
		connect = 1
		# If we were not connected we need te rewrite the conkyrc file
		if "Not connected" in netinfo_content :
			write = 1
	except :
		gw = ""
		# The gateway can't be found, we are not connected
		connect = 0
		# If we were connected we need to rewrite the conkyrc file
		if not "Not connected" in netinfo_content :
			write = 1

	open_netinfo.close()

	if connect :
		# Get the public IP
		try :
			request = urllib2.Request("http://www.dginio.free.fr/ip")
			ip_pub = urllib2.urlopen(request).read()
		except :
			ip_pub = "---"
	
		# ARP Table
		arp = execute("arp -an")
	
		# Check if the gateway is stuck in the ARP table
		if "PERM" in arp: gwState = "Static"
		else: gwState = "Dynamic"
	
		# MAC address of the gateway in the ARP table
		gwMac = re.compile(gw+'\) à (.*) \[').findall(arp)[0]
	
		# MAC address of the gateway with an ARP request
		gwMacDyn = getmacbyip(gw)
	
		# compare these address MAC to know if a potential ARP poisoning is running against us
		if gwMac == gwMacDyn: mitm = "OK"
		else: mitm = "${color3}MITM"
	
		# ifconfig of the current interface
		ifconfig = execute("ifconfig "+conf.iface)
	
		# get the netmask in the ifconfig
		mask = re.compile('Masque:(.*)').findall(ifconfig)[0]
	
		# CIDR netmask
		maskCidr = netmaskToBits(mask)
	
		# current ip address with ifconfig
		addr = re.compile('inet adr:(.*) B').findall(ifconfig)[0][:-1]
	
		# current mac address with ifconfig
		mac = re.compile('HWaddr (.*)').findall(ifconfig)[0]
	
		# get the DHCP server address in the file /var/lib/dhcp/dhclient.leases
		# Loop on the file, if the current iface is found, the next DHCP server address is for us
		findIface = 0
		for line in re.compile('.*').findall(open('/var/lib/dhcp/dhclient.leases','r').read()):
			if conf.iface in line: findIface = 1
			if findIface and "option dhcp-server-identifier" in line:
				dhcp = re.compile('option dhcp-server-identifier (.*)').findall(line)[0][:-1]
				findIface = 0
	
		# get all DNS servers in the file /etc/resolv.conf
		dns = ", ".join(re.compile('nameserver (.*)').findall(open('/etc/resolv.conf','r').read()))

		# arping on the local network > ips.txt
		fips = open(pathscript+"ips.txt","w")
		for ip in [t[1].psrc for t in arping(gw+"/"+maskCidr)[0][ARP]]: fips.write(ip+"\n")
		fips.close()
	
		# sort and uniq on the file ips.txt
		os.system("cat "+pathscript+"ips.txt |sort -n -t . -k 3,3n -k 4,4n |uniq > "+pathscript+"tmp ; mv "+pathscript+"tmp "+pathscript+"ips.txt")
	
		# read the file ips.txt
		fips = open(pathscript+"ips.txt","r").readlines()
	
		# each ip address is added in the array ips
		ips = []
		for ip in fips: ips.append(ip.strip())
	
		# ICMP request for each address in the array ips
		ans,unans=sr(IP(dst=ips)/ICMP(),timeout=1)
	
		# reply store in a dict with ttl
		reply = [(p[1].src,p[1].ttl) for p in ans[IP]]
	
		# keep only ip address which replied to the ping and write it in a tmp file
		noreply = []
		tmp = open(pathscript+"tmp","w")
		for line in fips:
			test = 0
			for ip in [p.dst for p in unans[IP]]:	
				if ip in line : test = 1
			if test : noreply.append(ip)
			else : tmp.write(line)
		tmp.close()
		
		# the file tmp replace ips.txt to keep only active ip address for the next scan
		os.system("mv "+pathscript+"tmp "+pathscript+"ips.txt")
		
		# building of the net var, it will contains all the network informations separated with a '&'
		net = conf.iface+"&"+addr+"/"+maskCidr+"&"+mac+"&"+gw+" - "+gwState+" - "+mitm+"&"
		if mitm == "OK": net += gwMac+"&"
		else: gwMac+" | "+gwMacDyn+"&"
		net += dhcp+"&"+dns+"&"+proxyPath+" - "+proxyState+"&"+ip_pub+"&"+" "*60+"Online : "+str(len(reply))+" - Offline : "+str(len(noreply))+"&"
		for ip,ttl in reply : net += " "*60+"   [+]  "+ip+" "*(17-len(ip))+str(ttl)+"\n"
		for ip in noreply : net += " "*60+"   [-]  "+ip+" "*(17-len(ip))+"?\n"
	
	else :
		# if we were not connected, the net var contains some empty fields and 'Not connected ?' instead of the iface
		net = "Not connected ?"+"&"*8
		conf.iface = ""
	
	open_netinfo = open(file_netinfo,"w")
	open_netinfo.write(net)
	open_netinfo.close()

	# if we need to rewrite the conkyrc
	if write :
		# conky vars
		goto = "100"
		bar = "270"
		refresh = "20"
		# titles
		t = ["SYSTEM","TOP","NETWORK","PUBLIC","HOSTS"]
		def title(n) : return "${voffset 7}${font DroidSans:bold:size=8.25}${color3}"+t[n]+"${offset 8}${color0}${voffset -1}${cpubar cpu0 1,"+str(374-len(t[n]*6))+"}"

		nb_proc = int(execute("cat /proc/cpuinfo | grep processor | wc -l"))
		cpu = []
		for i in range(4):
			if i < nb_proc : cpu.append("${color1}CP"+str(i)+" :$color0 ${cpu cpu"+str(i)+"}% ${goto "+goto+"}$color3${cpubar cpu"+str(i)+" 6,"+bar+"}\n")
			else : cpu.append("${color1}CP"+str(i)+" :$color0 none\n")

		# let's go
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
		title(2)+"${font}\n",
		"${color1}iface : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f1 }\n",
		"${color1}IP  : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f2 }\n",
		"${color1}MAC : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f3 }\n",
		"${color1}Gateway : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f4 }\n",
		"${color1}MAC : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f5 }\n",
		"${color1}DHCP server : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f6 }\n",
		"${color1}DNS server(s) : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f7 }\n",
		"${color1}Proxy : ${color0}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f8 }\n",
		"${color1}Downloaded : ${color0}${totaldown "+conf.iface+"}\n",
		"${color1}Uploaded   : ${color0}${totalup "+conf.iface+"}\n",
		"${color1}Download ${color0}${downspeed "+conf.iface+"}\n",
		"${color2}${downspeedgraph "+conf.iface+" 25, 330 FFB515 D70303 -t}\n",
		"${color1}Upload ${color0}${upspeed "+conf.iface+"}\n",
		"${color2}${upspeedgraph "+conf.iface+" 25, 330 FFB515 D70303 -t}\n",
		title(3)+"${font}\n",
		"${color1}${font :pixelsize=34} ${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f9 }${font}\n",
		"${offset 398}${voffset -781}"+title(4)+"${font}\n",
		"${color1}${texeci "+refresh+" cat "+file_netinfo+" | head -n 1 | cut -d'&' -f10 }\n",
		"${color0}${texeci "+refresh+" cat "+file_netinfo+" | cut -d'&' -f11 }\n"
		"${texeci "+auto_refresh+" sleep 10 && sudo "+pathscript+current_filename+"}\n"
		])
		conky.close()
	
	# If conky us not running, this script will do that for you in a screen
	if not (execute("ps aux | grep 'conky -c' | grep -v grep")): execute("screen -dmS conky conky -c "+file_conky)
