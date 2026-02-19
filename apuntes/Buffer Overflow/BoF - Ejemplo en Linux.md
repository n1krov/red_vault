---
Tema: "[[Buffer Overflow]]"
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

aca explico un ejemplo de buffer overflow

una maquina IMF de nombre. la de impossible mission force

una vez que tomas el control. tiene un binario corriendo y esta por el puerto 7788 con  `netstat -nat`

si estas en la maquina victima y ejecutasv `nc localhost 7788` 

te lleva a la interfaz imf, ahora con [[Ghidra]] para con ingenieria inversa obterner el agent id con el que se compara en el codigo poruqe te pide como un acceso

el cual es `48093572`

si sigues el flujo del codigo que esta en c podras darte cuenta que hay una funcion utiliza la funcion `gets()` la cual no controla limites como `fgets()`

el cual gets es potencialmente vector de BoF

