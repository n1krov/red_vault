---
Tema: "[[Indice]]"
---
>[!note]
>Constantemente a lo largo de las maquinas que resuelva voy a estar haciendo estas cosas. la idea es tener esto a mano, no copiar y pegar las cosas,sino mas bien leerlas y escribirlas para que me quede guardado en la cabeza. Quiero que me salga absolutamente naturalizado hacer esto. pero tener centralizado las cosas mas comuntes que voy hacer es una buena idea por si llego a olvidarme de alguna o no estoy aplicando algo. Tratare de poner buenas practicas y cosas que siempre se deben revisar
## reconocimiento
armar carpetas mkt{nmap, content, exploits}
tipico escaneo con [[nmap - Reconocimiento]]

Buscar en version de sistemas linux si es que se llega a enumerar en `launchpad`


## navegacion por web. 
- ver el codigo fuente siempre `ctrl + u`
- en los inputs de login revisar las sqli, SIEMPRE - basadas en booleanas y en tiempo al menos

independientemente si vemos tecnologias en un sistema o sus versiones tamien es util buscar vulnerabilidades con [[searchsploit]]
`searchsploit <tecnologia>`
si encuentras una puedes hacer
`searchsploit -x exploit`



## Escalada de Privilegios

generalmente si estas en un cms como wordpress en php existen archivos config que pueden por ahi mostrar credenciales

```sh
find -name \*config\* 2>/dev/null 
```

Busqueda de archivos con privilegios SUID
```sh
find / -perm -4000 2>/dev/null
```


util tambien catear el `.bash_history`

tambien listar timers de crontabs

```sh
systemctl list-timers
```
