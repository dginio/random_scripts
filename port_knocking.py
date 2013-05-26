#!/usr/bin/python
#coding:utf-8

# Antoine BOTTE 16/01/2013 port-knocking scapy

#Importation des librairies
import sys,os
from scapy.all import *

#Désactiver le mode verbose
conf.verb = 0

#Définition des variables de base
interface="wlan0"
lPorts=[12,34,56]
portUtile=80

#Désactivation des règles iptables, puis ajout d'une règle bloquant tout le trafic entrant
os.system('iptables -F && iptables -X && iptables -A INPUT -i '+interface+' -j DROP')

#Initialisation du compteur de knock à 0
knocking = 0

#Fonction appelé si le paquet est de type TCP
def knock(paquet):
	global knocking												#Permet l'accès a la variable global knocking
	if paquet.dport == lPorts[knocking] : knocking += 1			#Incrémente knocking si le port destination correspond à celui attendu
	else : knocking = 0											#Sinon on replace knocking à 0 pour réinitialiser la séquence
	
	if knocking == len(lPorts):									#Une fois que tous les ports du tableau sont knocké
		#On autorise la derniere IP source à se connecter au portUtile dans iptables
		os.system('iptables -A INPUT -p tcp --destination-port '+str(portUtile)+' -s '+str(paquet[IP].src)+' -j ACCEPT')
		#On replace knocking à 0 pour réinitialiser la séquence
		knocking = 0

#Sniff les paquets TCP
sniff( count = 0, store = 0, filter = "tcp", lfilter = lambda p: p.haslayer(TCP), prn = knock )
