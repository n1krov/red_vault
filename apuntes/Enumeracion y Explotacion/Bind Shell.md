### Bind Shell

En una **bind shell**, la máquina objetivo abre un puerto específico y espera a que el atacante se conecte a él, actuando como servidor. El atacante, actuando como cliente, se conecta a este puerto para obtener acceso al sistema. Este enfoque puede ser menos efectivo en entornos donde los firewalls bloquean conexiones entrantes no autorizadas.

[GeeksforGeeks](https://www.geeksforgeeks.org/difference-between-bind-shell-and-reverse-shell/?utm_source=chatgpt.com)

**Características:**

- **Iniciador de la conexión:** Atacante.
- **Dirección de la conexión:** Desde el atacante hacia la víctima.
- **Desventaja principal:** Susceptible a ser bloqueada por firewalls que filtran conexiones entrantes.

[[Enumeracion y Explotacion]]