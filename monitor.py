import nmap
import socket

def runScan():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.*/24', arguments='-n -sP -PE')
    
    #hostlist = ' '.join(nm.all_hosts())
    #nm.scan(hosts=hostlist, arguments='-n -sP -PE')
    
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s ' % host)
        try:
            result = socket.gethostbyaddr("" + host + "")
            print(result[0])
        except:
            print("Could not identify host")

'''
Loops through all potential IPs on the local network, but detects inactive devices
'''
def runOtherScan():
    hostList = []
    for i in range(1, 255):
        try:
            host = "192.168.1."+ str(i)
            result = socket.gethostbyaddr(host)
            hostList.append((host, result[0]))
        except:
            pass
        
    print(hostList)

if __name__ == "__main__":
    runScan()
    #runOtherScan()
