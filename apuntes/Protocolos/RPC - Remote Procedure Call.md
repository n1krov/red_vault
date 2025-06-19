
# 🧩 Remote Procedure Call (RPC)

> Una técnica que permite que un programa ejecute código en otra máquina como si fuese una función local, **facilitando la comunicación entre sistemas** en la misma red o en redes separadas.

---

## 🧠 Concepto

**RPC (Remote Procedure Call)** es un **protocolo** que permite que un **cliente invoque procedimientos o funciones que se ejecutan en un servidor remoto**, como si fueran funciones locales.

🔍 Esto **abstrae la complejidad de la red**, permitiendo que los desarrolladores se enfoquen en la lógica de negocio, sin preocuparse por cómo se comunican los sistemas por debajo.

---

## ⚙️ Funcionamiento

1. 🧑‍💻 El **cliente** llama a una función remota **como si fuera local**.
2. 📡 Se **envía un mensaje** por red al **servidor** con:
   - el nombre de la función
   - los parámetros necesarios
3. 🖥️ El **servidor ejecuta** la función solicitada.
4. 📦 El **resultado** se envía **de vuelta al cliente**.

> Todo el proceso es transparente para el programador.

---

## ✅ Beneficios

- 🎯 **Simplicidad**: Permite desarrollar aplicaciones distribuidas **sin lidiar con los detalles de red**.
- 🧩 **Abstracción**: Oculta la lógica de comunicación, y permite interoperabilidad entre sistemas y lenguajes.
- 📈 **Escalabilidad**: Facilita agregar nuevos servicios o funcionalidades al sistema distribuido.

---

## 💡 Ejemplos de uso

- 🪟 **Sistemas operativos modernos** (como Windows):
  - Servicios de impresión 🖨️
  - Conexiones de red 🌐
  - Servicios de fax 📨

- 📁 **Sistemas de archivos de red**:
  - *NFS (Network File System)* usa RPC para permitir el acceso remoto a archivos como si fueran locales.

- 🌐 **Aplicaciones distribuidas**:
  - Comunicación entre servicios o microservicios en arquitecturas distribuidas.

---

## 🧭 Resumen visual

```mermaid
sequenceDiagram
    participant Cliente
    participant Red
    participant Servidor

    Cliente->>Servidor: Llamada RPC (función + parámetros)
    Servidor->>Servidor: Ejecuta función
    Servidor-->>Cliente: Devuelve resultado
````


> 📝 **Conclusión**: RPC es una base fundamental de los sistemas distribuidos modernos, ofreciendo una forma eficiente y elegante de comunicar componentes a través de la red sin sacrificar simplicidad ni escalabilidad.


----

[[protocolos]]