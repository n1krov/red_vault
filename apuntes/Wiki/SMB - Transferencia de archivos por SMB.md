---
Tema: "[[wiki]]"
---

Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas.  
Respetá enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---


Maquina atacante -  creamos servidor smb con [[impacket-smbserver]]

```sh
impacket-smbserver folder $(pwd) -smb2support
```

aqui estoy creando un recurso compartido a nivel de red con nombre folder que este sincronizado con mi ruta actual con pwd 
ademas le damos soporte a la version 2 de smb

si la maquina victima es una windows  en el explorador de archivos en el buscador puedes acceder al folder colocando

```powershell
\\ip_atacante\folder
```

luego el bytearrray txt lo copiamosa esa ruta y listo
