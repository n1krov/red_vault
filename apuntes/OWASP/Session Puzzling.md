
llamado session fixation attack o session variable overloading

pequeña teoria

---

# Practica

empezamos haciendo

docker pull blabla1337/owasp-skf-lab:sessionpuzzle


despues desplegamos el contenedor

docker run -dit -p 127.0.0.1:5000:5000 blabla1337/owasp-skf-lab:sessionpuzzle

donde
- d:
- i:
- t:
aplicamos port forwarding
le pasamos la imagen



una vez desplegado vamos a ver el home ingresando por localhost:5000/

> [!NOTE]
> el session puzzling aqui en esta maquina lo imitan haciendo un cookie manipulation 
> la idea es que interactuas con el usuario.

iniciamos sesion en el panel con admin admin (usuario y contraseña) minetras lo rastreamos con burpsuite

al hacer ctrl+shift+c en el navegador -> en la parte de storage podemos ver la cookie de sesion

hay una herramienta que es un sitio web llamado [[jwt io]] donde le pasas la cookie y si tu cookie tiene dos puntos probablemente sea un json web token para detectarte los headers, payload etc..



 

---
[[OWASP]]