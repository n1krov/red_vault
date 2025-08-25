
---

### Sustitucion

Para sustituir una coincidencia en cada linea de codigo puedes hacer `:` y luego escribir
```css
%s/<caracteres_a_sustituir>/<caracteres_nuevos>
```

Tambien puedes agregar una `/g` al final para que detecte mas de una coincidencia por linea

```css
%s/<caracteres_a_sustituir>/<caracteres_nuevos>
```

Tambien puedes agregar un `c` al final para que te pida confirmacion antes de hacer el cambio

```css
%s/<caracteres_a_sustituir>/<caracteres_nuevos>/gc
```

Puedes usar `&` para referenciar el texto que se va a sustituir

```css
%s/<caracteres_a_sustituir>/<caracteres_nuevos>&
```


---
[[apuntes/herramientas/herramientas]]