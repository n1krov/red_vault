---
Tema: "[[Buffer Overflow]]"
---

Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas. 
lo que este encerrado entre {indicaciones para LLM} son indicaciones para ti sobre lo que tienes que hacer en ese punto.
Respetá  OBLIGATORIAMENTE enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---

## Inicio

se va a trabajar sobre [MiniShare](https://sourceforge.net/projects/minishare/) explotaremos eso, tiene vulnerabilidad de buffer obverflow

minishare te va a dar un servicio http por el puerto 80

algo que necesitamos es que ademas este habilitado el uso de [[telnet]] para poder trabajar sobre el script de pyhton

para eso en telnet te conectas de la siguiente manera

```sh
telnet <ip> <puerto>
```

aplicar `GET / HTTP/1.1` + enter + enter

eso se programara en el script


## Fase Fuzzing

alcarar qeu el bof ocurre en este punto:
-  `GET AAAAAAA... HTTP/1.1`

por lo que se empieza por descubrir donde estan los registros el `EIP` y el `ESP`