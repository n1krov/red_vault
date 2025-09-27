---
Tema: "[[Escalada de Privilegios]]"
---

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

algo de teoria


---
practica
maquina pluck: 1 de vulnhub

para empezar
la url tiene un estilo como 
http://localhost/index.php?page=admin.php

esto permite jugar con [[Tecnica Wrapper]] 

pero lo importante es que se pueden listar archivos especificos como el etc passwd
http://localhost/index.php?page=/etc/passwd

encontraremos un archivo backup.sh

![[Pasted image 20250927172129.png]]

si miramos que tiene este archivo nos sale

![[Pasted image 20250927172221.png]]

esto dice que hace backups en el dir backups y podemos obtenerlo via [[tftp]]

extraemos con 
descomprimimos el backup con 
tar -xf backups/backup.tar.gz

y al descomprimirlo se pueden ver archivos varios

hay un directorio que contiene claves privadas y publicas

en nuestro caso la usamos la key  id_key4

ssh paul@192.168.111.46 -i id_key4

nos da acceso a la maquina como paul

pero como vimos en el etcpasswd paul esta ejecutando de entrada /home/paul:/usr/bin/pdmenu 


y pdmenu es un binario que tiene una opcion de edit file al menos en esta maquina de prueba
AHI LE PODEMOS PONER EL etc/passwd

pero nos abre vi

en [[GTFOBins]] nos da una forma para lanzar una shell abusando de vi

podemos hacer
:set shell=/bin/bash
:shell

y ya, ahora para tener mejor comodida 
export TERM=xterm" para ctrl l y demas


ahora la escalada de privilegios

al hacer id no estamos en ningun grupo especial viendo lo de [[Post Explotacion - Linux]] para aplicar reoconicimiento y saber donde estamos parados

ver la distro
cat /etc/os-release

a nivel de kernel
uname -a

