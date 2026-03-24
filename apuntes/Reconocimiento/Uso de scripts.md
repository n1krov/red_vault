> Nmap tiene varios scripts dedicados a escaneos a puertos especificos, ennumeracion de archivos, ataques fuerza bruta, fuzzing, etc a disposicion. Estan escritos en mse, un lenguaje de programacion similar a bash, se utiliza sobre todo para configuracion.
	**Nmap Scripting Engine (NSE)** es la funcionalidad que permite automatizar tareas de red mediante scripts, y utiliza el **lenguaje Lua** para su configuración y desarrollo.


- `.nse` es la extension de script de nmap listos para usar
```
locate .nse
```
- listamos todos los scripts disponibles.

### Scripts mas utilizados
- Para auditar un puerto ftp
	`ftp-anon.nse`
- Para auditar un http
	`http-robots.txt.nse`
### Categorias de nmap
- Cada script pertenece a una categoria, para listar todas las categorias disponibles:
```
locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u (| wc -l)
```


```
nmap -p22 192.168.100.1 --script="vuln and safe"
```
- `--script="categoria1 and categoria2"` para filtrar los script con determinada/s categoria/s
- `--script="cat1 or cat2"` script solo con cat1 o cat2

- Para fuzzing o fuerza bruta sobre una pagina web y ennumerar rutas:
```
nmap -p80 192.168.100.1 --script http-enum
```

### Comandos utiles e interesantes
```
python3 -m http.server 80
```

Escanear si hay un servicio
```
lsof -i:80
```

En que ruta del sistema se ejecuta ese servidor
```
pwdx id_proceso
```

## Comandos utilizados
- [[python3]]
- [[locate]]
- [[lsof]]
- [[pwdx]]