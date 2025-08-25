
> 📝 **Nota**: el prefijo por defecto es `Ctrl + b`. Si lo cambiás, reemplazalo en tu cabeza mientras leés esto.

## 🚀 **Comienzo Rápido**

| Acción                  | Comando                       |
| ----------------------- | ----------------------------- |
| Crear una nueva sesión  | `tmux` o `tmux new -s nombre` |
| Listar sesiones activas | `tmux ls`                     |
| Adjuntarse a una sesión | `tmux attach -t nombre`       |
| Desconectarse (detach)  | `Ctrl + b`, luego `d`         |
| Matar una sesión        | `tmux kill-session -t nombre` |
## 📐 **Paneles (Splits)**

|Acción|Comando|
|---|---|
|Dividir horizontalmente|`Ctrl + b`, luego `%`|
|Dividir verticalmente|`Ctrl + b`, luego `"`|
|Mover entre paneles|`Ctrl + b`, luego ← ↑ ↓ →|
|Redimensionar panel|`Ctrl + b` luego `:` → `resize-pane -L 10` (izq) o usa `Ctrl + b` y `Alt + flecha` si está configurado|
|Cerrar panel actual|`exit` o `Ctrl + d`|
|Cambiar el orden de paneles|`Ctrl + b`, luego `Ctrl + o`|

## 🪟 **Ventanas (Tabs)**

|Acción|Comando|
|---|---|
|Nueva ventana|`Ctrl + b`, luego `c`|
|Cambiar ventana|`Ctrl + b`, luego `n` (siguiente), `p` (anterior)|
|Ir a ventana N|`Ctrl + b`, luego número `0–9`|
|Renombrar ventana|`Ctrl + b`, luego `,`|
|Cerrar ventana|`exit` dentro de la ventana|

## 📋 **Sesiones**

| Acción            | Comando                                               |
| ----------------- | ----------------------------------------------------- |
| Cambiar de sesión | `Ctrl + b`, luego `s`                                 |
| Renombrar sesión  | `Ctrl + b`, luego `:` → `rename-session nuevo_nombre` |
| Matar sesión      | `Ctrl + b`, luego `:` → `kill-session`                |
## 🧠 **Modo Copiar y Pegar**

|Acción|Comando|
|---|---|
|Entrar al modo copiar|`Ctrl + b`, luego `[`|
|Mover cursor|Flechas ↑ ↓ ← →|
|Iniciar selección|Espacio|
|Copiar|Enter|
|Pegar en panel|`Ctrl + b`, luego `]`|

🔧 Tip: para usar el portapapeles del sistema con `xclip` o `xsel`, configurá `tmux` con:

```tmux
bind-key -T copy-mode-vi y send -X copy-pipe-and-cancel "xclip -selection clipboard -in"
```

## ⚙️ **Comandos útiles desde línea**

|Acción|Comando|
|---|---|
|Mostrar todos los atajos|`tmux list-keys`|
|Mostrar atajos de un modo|`tmux list-keys -T copy-mode-vi`|
|Ver configuración activa|`tmux show-options -g`|
|Recargar config (`.tmux.conf`)|`Ctrl + b`, luego `:` → `source-file ~/.tmux.conf`|


---

## 🛠️ **Tips Avanzados**

- 🔄 **Sincronizar entradas en todos los paneles**:
```sh
Ctrl + b, luego :
setw synchronize-panes on
```
(desactivar con `off`)
- 📦 **Script de inicio personalizado**:
```sh
tmux new-session -s dev \; \
  split-window -h \; \
  split-window -v \; \
  select-pane -t 0 \; \
  send-keys 'vim .' C-m
```


[[apuntes/herramientas/herramientas]]