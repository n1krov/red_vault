   
import sys, signal, requests

def signal_handler(signal, frame):
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)

 
puertos_tcp_comunes = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCbind
    135,   # MS RPC
    139,   # NetBIOS Session Service
    143,   # IMAP
    443,   # HTTPS
    445,   # Microsoft-DS (SMB)
    993,   # IMAPS
    995,   # POP3S
    1723,  # PPTP
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
    8080,  # HTTP Alternate
    8443,  # HTTPS Alternate
    8888,  # HTTP Alternate (common for web apps)
    9000,  # PHP-FPM, Docker, etc.
    9090,  # HTTP Alternate (common for web apps)
    10000, # Webmin
    27017, # MongoDB
    27018, # MongoDB
    27019, # MongoDB
    28017, # MongoDB (HTTP interface)
    33060, # MySQL
    49152, # Windows RPC
    49153, # Windows RPC
    49154, # Windows RPC
    49155, # Windows RPC
    49156, # Windows RPC
    49157, # Windows RPC
    50000, # DB2
    50030, # Hadoop
    50070, # Hadoop
    50075, # Hadoop
    50090, # Hadoop
    60000, # Custom (common in some apps)
    60010, # HBase
    60030, # HBase
    60050, # HBase
    60070, # HBase
    60075, # HBase
    60090, # HBase
    60100, # Custom (common in some apps)
    60110, # Custom (common in some apps)
    60120, # Custom (common in some apps)
    60130, # Custom (common in some apps)
}


# a tener encuenta que vamos a iterar por cada uno de los puertos


main_url= 'http://192.168.1.11'

squid_proxy={'http': 'http://192.168.1.11:3128'}


def main():
    for tcp_port in puertos_tcp_comunes:
        try:
            response = requests.get(main_url +":"+ str(tcp_port), proxies=squid_proxy)
   
            if response.status_code != 503:
                print(f"El puerto {tcp_port} está abierto")

        except requests.exceptions.ConnectionError:
            print(f"El puerto {tcp_port} no está abierto")

        



if __name__ == "__main__":
    main()

