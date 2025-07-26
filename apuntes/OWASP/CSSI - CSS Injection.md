
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