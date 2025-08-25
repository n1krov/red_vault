
## 🧾 `base64` – Explicación de opciones

El comando `base64` se usa para **codificar** o **decodificar** datos en el formato **Base64**, muy útil para enviar datos binarios como texto (por ejemplo, en correos o JSON).

### 📌 Uso básico:

```bash
base64 archivo.txt       # Codifica en base64 el contenido de archivo.txt
base64 -d archivo.b64    # Decodifica un archivo codificado en base64
```

---

### 🛠️ Opciones explicadas

| Opción                    | Significado Sencillo                                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `-d` o `--decode`         | **Decodifica** la entrada desde base64 a su forma original.                                                        |
| `-i` o `--ignore-garbage` | **Ignora caracteres que no pertenecen a base64** al decodificar. Útil si el texto tiene basura.                    |
| `-w` o `--wrap=COLS`      | **Divide las líneas codificadas cada `COLS` caracteres** (por defecto es 76). Usa `0` para evitar saltos de línea. |
| `--help`                  | Muestra la ayuda del comando.                                                                                      |
| `--version`               | Muestra la versión de `base64`.                                                                                    |

---

### 🧪 Ejemplos prácticos

**Codificar un texto simple:**

```bash
echo "Hola Lautaro" | base64
# Resultado: SG9sYSBMYXV0YXJvCg==
```

**Decodificar ese mismo texto:**

```bash
echo "SG9sYSBMYXV0YXJvCg==" | base64 -d
# Resultado: Hola Lautaro
```

**Evitar saltos de línea al codificar:**

```bash
echo "Mensaje largo" | base64 -w 0
```



----
[[apuntes/herramientas/herramientas]]