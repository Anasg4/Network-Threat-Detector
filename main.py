import winsound, time
from scapy.layers.l2 import *
from scapy.all import *
from scapy.layers.dot11 import *

def identifikasi(target_ip):
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        clients = []
        time.sleep(2)
        for sent, received in result:
            clients.append(received.psrc)

        for word in clients:
            if word not in phase1:
                phase1.append(word)
        if len(phase2) == 0:
            pass
        else:
            if len(phase1) > len(phase2):
                print ("="*50,"\nAncaman / Threat >>> ",phase1[-1])
                for x in range(5):
                    winsound.Beep(700, 500) #For Windows , if u linux user u can use beepy or others
                pass
            else:
                print("="*50,"\nTidak ada ancaman / No Threat")
                time.sleep(2)
                pass

        print("Router IP >> ", ip, "\n")
        print("\nSemua yang terkoneksi dalam satu jaringan")
        print("IP")

        for client in clients:
            print(client)
        for word in phase1:
            if word not in phase2:
                phase2.append(word)
if __name__=="__main__":
    # clients = []
    phase1 = [] #you can put your legal ip here
    phase2 = []
    print("Author github.com/Anasg4 \n")
    ip = input("Contoh inputan / exmple for input >>> 192.168.1.1/24\nMasukan IP dan Port, port default /24 : ")
    if ip == "n":
        target_ip = "192.168.100.1/24"
    else:
        target_ip = ip
    print(target_ip)
    try:
        identifikasi(target_ip)
    except:
        print("\n\nWrong Router Address. please restart this tool and input the Address Correctly")
