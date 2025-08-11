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