# 🖧 ¿Qué es un Clúster?

Un **clúster** es un conjunto de computadoras (llamadas **nodos**) que cooperan entre sí para ofrecer **mayor rendimiento, disponibilidad o escalabilidad** que una sola máquina individual.

---

## 🔧 Tipos de Clústeres

### 🏭 Clúster de Alto Rendimiento (HPC)
- Usado en simulaciones científicas, cálculos complejos, IA, etc.
- Conecta múltiples nodos para resolver tareas en paralelo.

### 🔁 Clúster de Alta Disponibilidad (HA)
- Asegura que los servicios estén siempre activos.
- Si un nodo falla, otro toma el control automáticamente.
- Ej: clúster de bases de datos o servidores web.

### 📈 Clúster de Carga Balanceada
- Distribuye peticiones entre varios nodos.
- Mejora el rendimiento y evita sobrecargas.
- Usado en aplicaciones web de alto tráfico.

### 🗃️ Clúster de Almacenamiento
- Une varios discos/nodos para ofrecer almacenamiento distribuido.
- Ej: Ceph, GlusterFS.

---

## 💬 Ejemplo Práctico

Una aplicación web con miles de visitas por segundo no puede depender de un solo servidor. Entonces:

- Se arma un clúster con 3 servidores web.
- Se usa un balanceador (Nginx, HAProxy).
- Las peticiones se distribuyen entre los nodos.
- Si uno cae, los otros siguen respondiendo.

---

## 🧱 Componentes de un Clúster

- **Nodos:** computadoras individuales que conforman el clúster.
- **Red interna:** para la comunicación entre nodos.
- **Gestor del clúster:** software que coordina las tareas.
- **Almacenamiento compartido (opcional):** usado en ciertos tipos de clústeres.

---

## 🧰 Herramientas Comunes

| Herramienta | Uso |
|-------------|-----|
| `Kubernetes` | Orquestación de contenedores |
| `Pacemaker` + `Corosync` | Alta disponibilidad |
| `Ceph` / `GlusterFS` | Almacenamiento distribuido |
| `Slurm` | HPC en entornos científicos |

---

## ✅ Ventajas

- Alta disponibilidad del servicio
- Escalabilidad horizontal
- Redundancia ante fallos
- Optimización de recursos

## ❌ Desventajas

- Mayor complejidad técnica
- Costos de infraestructura
- Configuración y mantenimiento más exigentes

---

## 📚 Lecturas Recomendadas

- [Kubernetes Docs](https://kubernetes.io/docs/home/)
- [Pacemaker](https://clusterlabs.org/pacemaker/)
- [Ceph](https://docs.ceph.com/en/latest/)

[[fundamento de servidores]]