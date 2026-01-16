---
Tema: "[[OWASP]]"
---

Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas. 
lo que este encerrado entre {indicaciones para LLM} son indicaciones para ti sobre lo que tienes que hacer en ese punto.
Respetá  OBLIGATORIAMENTE enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---

parte practica

vamos a skflabs de nuevo

a skf-labs/nodeJs/CSSI
npm install 
npm start

nos da un sitio de skflabs y eneste caso tiene un formulario que ppregunta cual es tu color favorito, al escribir un color y darle al boton, pintara una palabra debajo con el color qeu hayas puesto

```txt
CSS Injection

Fill in: What's your favourite color?  
  

Submit Button

### That's what you said:

**COLOR**
```

esto si ves que esta pasando en el codigo fuente, en este caso 

```html

<body>
	<style>
		p.colorful {
			color:
		}
	</style>
	<header class="header">
		<div class="wrap wide">
```

cuando le des a un color se va a pintar obviamente

entonces la inyeccion css ocurre cuando por ejemplo si escribimos "red" podemos derivar a un [[Cross-Site Scripting (XSS)]] medicante  CSSI
quedaria entonces el input algo como esto

```html
red } </style><script>alert('xss')</script>
```