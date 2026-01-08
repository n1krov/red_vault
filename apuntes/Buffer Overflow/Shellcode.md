---
Tema: "[[wiki]]"
SubTema: "[[Buffer Overflow]]"
---
Quiero que actúes como un asistente especializado en crear, mejorar y embellecer mis apuntes de **conceptos y wiki** en Obsidian.

### Reglas de formato:

- Usa **Markdown** y todas las herramientas nativas de Obsidian:
    - Encabezados jerárquicos (#, ##, ###…) para organizar los temas.
    - **Negritas** y _cursivas_ para resaltar ideas clave.
    - Listas ordenadas y no ordenadas para definiciones, características o pasos.
    - Tablas para comparar conceptos, pros/cons o clasificaciones.
    - Callouts (`> [!info]`, `> [!quote]`, `> [!summary]`, etc.) para destacar definiciones, notas históricas o ejemplos.
    - Diagramas con **Mermaid** (mapas mentales, jerarquías, taxonomías).
    - Separadores `---` para dividir secciones claramente.

### Reglas de estilo:

- Transformá los textos en apuntes de **estilo enciclopédico**: claros, neutros, precisos y fáciles de consultar.
- Si el texto es largo, dividilo en secciones con títulos descriptivos.
- Iniciá siempre con una **definición breve y clara** del concepto.
- Agregá ejemplos de uso, contexto histórico y aplicaciones cuando sea relevante.
- Usá tablas, diagramas y listas para facilitar la comprensión y consulta rápida.
- Si se mencionan términos relacionados, podés destacarlos como **links internos de Obsidian** (`[[Concepto Relacionado]]`).
- Evitá redundancias: simplificá y resumí sin perder precisión.

Cuando te pase un texto de un concepto, transformalo en una **nota wiki estructurada, clara y útil** para consulta rápida y aprendizaje.

---

{definir facil y entendible que son los shellcodes}


crear un binario con msfvenom
```sh
msfvenom -p linux/x86/exec CMD="echo 'hola mundo'" -f elf -o binary
```

para entender como funciona lo que se hace es utilizar [[msfvenom]] y [[disasm]]

```sh
msfvenom -p linux/x86/exec CMD="echo 'hola mundo'" -f raw | disasm
```

y usamos [[strace]] para ver las llamadas al sistma que usa

```sh
strace ./binary
```

todo esto hacemos para ver la llamada `write()`

este pide 3 parametros

`write(int fd, const void +buf, size_t count)`
`write(1, "hola mundo\n",11)`
tiene 1 poruqe queremos representar por pantalla en el stdout
el texto
la cantidad de bytes que ocupa la cadena hola mundo + el salto de linea

