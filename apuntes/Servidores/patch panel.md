## 🧩 ¿Qué es una **patchera**?

Una **patchera** es un **panel de conexiones** (como una "central de enchufes") que se usa para **organizar y enrutar los cables de red** dentro de un datacenter o sala de servidores.

### 📦 Básicamente:

Es un panel con **puertos RJ45 (Ethernet)** en el frente, y **cables UTP o STP conectados por detrás** (normalmente crimpados o conectados a bloques tipo 110 o Krone).

---

### 🔌 ¿Para qué sirve?

1. 🔄 **Conectar y reconectar fácilmente** dispositivos de red (switches, servidores, firewalls, etc.) sin tocar los cables estructurales.
    
2. 📚 **Organizar** la red: todo el cableado va a un solo lugar, etiquetado.
    
3. ⚡ **Evitar desgaste** en equipos caros: en lugar de enchufar directamente en el switch, conectás en la patchera.
    
4. 🛠️ **Facilitar mantenimiento** y pruebas: podés cambiar conexiones sin desorden.
    

---

### 🧠 ¿Cómo funciona?

Imaginá que tenés un rack con un switch arriba, servidores abajo y una patchera al medio. El flujo sería así:

```text
[Switch] <---> [Patchera] <---> [Cableado estructurado de la empresa]
```

- La patchera se conecta al **switch** usando **"patch cords"** (cables cortos de red).
    
- Detrás de la patchera llegan los **cables de red desde las paredes, oficinas o pisos del edificio**.
    
- Entonces, desde el punto de vista de red, es un **nodo de interconexión física**, no activa, solo pasiva.
    

---

### 📷 ¿Cómo se ve?

Visualmente, una patchera parece una **regla negra horizontal con muchos puertos numerados** (como 24 o 48 bocas RJ45), y va montada en un rack.

---

### 📎 Tip extra:

En datacenters grandes también existen **patcheras de fibra óptica**, que cumplen el mismo propósito, pero con conectores **LC, SC, ST** en lugar de RJ45.


[[fundamento de servidores]]