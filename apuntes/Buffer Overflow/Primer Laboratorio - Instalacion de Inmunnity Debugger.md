---
Tema: "[[Buffer Overflow]]"
---

Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas.  
Respetá enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---

vamos a trabjar con un w7 de 32 bits home basic 
el enlace de descarga esta [aqui](https://archive.org/download/hi-tn-fi-nd.-com-windows-7-home-basic-32-bit-64-bit/_HiTnFiND.COM_Windows_7_Home_Basic_32Bit_64Bit.iso)
instalas en un hipervisor como VMARE o VIRTUALBOX
dentro de ese SO instalamos [[Inmunnity Debugger]] que esta solo para windows, esto requiere python y mona.py que lo puedes encontrar en este [repo](https://github.com/corelan/mona.git)
el codigo por si quieres hacer [[wget]]

 es este:
```bash
wget https://raw.githubusercontent.com/corelan/mona/refs/heads/master/mona.py
```

una vez instalado eso debemos [[Deshabilitar DEP en Windows 7]] esto es para que las instrucciones de memoria 
puedan ser ejecutadas en el stack mediante el shellcode y el dep es una proteccion

ese script de python hay que meterlo en C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands

tambien como en la fase de escaneo la maquina no devuelve nada puertos abiertos ni trazas ICMP, debemos deshabilitar el firewall de windows

y para que no se nos olvide lo hacemos asi:

vas a firewall y le das a turn off a todo

y tambien descargamos SLMail que es un servidor SMTP vulnerable a buffer overflow

este una vez instalado abre el puerto 25 y el 110 y el 110 es el vulnerable

si hacemos con [[searchsploit]]
```bash
searchsploit slmail 5.5
```

encontraremos scripts relacionados con un campo PASS que significa que un campo es vulnerable a buffer overflow

una vez configurado el SLMAIL y el inmunnity debugger y deshabilitado el firewall

reiniciamos y podemos ver que si nos conectamos con [[telnet]] al puerto 110 nos pide usuario y pass
```bash
telnet ipvictima  110
```


