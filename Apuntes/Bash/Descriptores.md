---

---

---


`exec` -> descriptor de archivo

`exec 3<> nombre` -> archivo con capacidad de lectura y escritura en el descriptor 3
- `<`  -> Lectura
- `>`  -> Escritura


`whoami >&3`  -> Enviando el output de whoami al descriptor 3

`exec 3>&-` ->  `>&-` hace que ese descriptor se cierre