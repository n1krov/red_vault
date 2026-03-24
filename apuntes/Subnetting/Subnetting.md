### ¿Qué es?
- En una empresa con muchos dispositivos conectados a la misma red dividirla es clave para *no desperdiciar direcciones IP* y hacerlo de *forma segura*.
- La mascara de red *255.255.255.0* tiene disponibles 254 direcciones IP para routers o dispositivos conectados a esa subred que, a su vez, puede dividirse en mas subredes.
- Una mascara de */24* por ejemplo son *$(32-24) bits disponibles*, es decir, 8 bits equivalentes a *2^8 y 256* direcciones disponibles.
- La cantidad de bits que conforman una direccion IP es 32, ya que son 4 octetos de 1s y 0s.
- Entonces si tenemos una mascara de 24 bits significa que hay 24 bits fijos y el resto pueden variar.
- De alli se puede volver a dividir pero siempre en potencias de 2.
- Podemos crear subredes de 8 direcciones, 16, 32, 64, 128 y 256. Pero para la cantidad final de hosts debemos restar dos porque se utiliza una direccion como puerta de entrada o enlace y otra direccion para broadcast, la primera y la última.
### CIDR (Classless Inter-Domain Routing)
- Enrutamiento de direcciones sin clases.
- Sirve para asignar y gestionar direcciones IP en un rango completo de direcciones.
- Se representa como IP/x, donde x es el valor de bits fijos, los restantes se pueden variar para asignar a los dispositivos de esa red.

![[Pasted image 20251202172644.png|950]]

![[Pasted image 20251202175144.png]]

Enlace para calcular https://www.ipaddressguide.com/cidr 

### Truco para calcular el comienzo
**1) Calcular el SALTO**
```
Salto = 256 − (octeto de la máscara donde NO es 255)
```
Ej:
- /23 → 255.255.254.0 → salto **2**
- /26 → 255.255.255.192 → salto **64**
- /28 → 255.255.255.240 → salto **16**

**2) Encontrar el BLOQUE donde cae la IP**
Tomá el octeto de la IP correspondiente y dividilo por el salto:
```
bloque = floor(IP_octeto / salto)
```

**3) Network ID**
```
NetworkID_octeto = bloque × salto
```
Los octetos posteriores → **0**

**4) Broadcast**
```
Broadcast_octeto = (bloque × salto) + salto − 1
```
Octetos posteriores → **255**

**MICROEJEMPLOS (rápidos y memorables)**

**IP 192.168.1.50/23**
Salto: 2 (3er octeto)  
1 cae en 0–1  
✔ Network ID: **192.168.0.0**  
✔ Broadcast: **192.168.1.255**

**IP 10.0.5.20/22**
Salto: 4  
5 cae en 4–7  
✔ Net: **10.0.4.0**  
✔ Brd: **10.0.7.255**

**IP 192.168.10.200/28**
Salto: 16  
200 cae en 192–207  
✔ Net: **192.168.10.192**  
✔ Brd: **192.168.10.207**

# Ejercicios
## 192.168.10.100/25
### Mascara
255.255.255.128
### Cantidad de hosts
128 - 2 = 126 direcciones utilizables
### Puerto de enlace o Network ID
192.128.10.0
### Direccion Broadcast
192.128.10.127

## 192.168.12.90/20
### Mascara
255.255.240.0
### Cantidad de hosts
4096 - 2 = 4094 direcciones utilizables
### Puerto de enlace o Network ID
192.168.0.0
### Direccion Broadcast
192.168.15.255



# Trucos para subnetting
### Binario

**192.168.12.10/13**
10100000.10101000.00001100.00001010 --> (192.168.12.10)
11111111.11111000.00000000.00000000 --> (255.248.0.0 --> **MASCARA**) 
|-----------------------------------------------------------------| [AND]
10100000.10101000.00000000.00000000 --> (192.168.0.0 --> **NETWORK ID**)
10100000.10101111.11111111.11111111 --> (192.175.255.255 --> **BROADCAST**)

**Cantidad de hosts** --> 2^(32-13) = 524288

### ¿Que hice?
- 1er linea: es la direccion IP en binario, separado por puntos.
- 2da linea: es la cantidad de 1s tantas veces como /x corresponda y despues 0s.
- 3er linea: se realiza una operacion entre la 1er y 2da linea de AND. Si ambos numeros son 1 se escribe 1, sino 0.
- 4ta linea: Se escriben los mismos numeros de la 3er linea tantas veces como /x corresponda y despues 1s.

