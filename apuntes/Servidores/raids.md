---
Tema: "[[fundamento de servidores]]"
---

## **1. ¿Qué es RAID?**
RAID es una técnica que combina múltiples discos duros (HDD/SSD) en una única unidad lógica para mejorar el **rendimiento**, la **capacidad** y/o la **tolerancia a fallos**. Se usa en servidores, NAS y sistemas críticos.

---

## **2. Niveles de RAID Principales**
### **RAID 0 (Striping)**
- **Cómo funciona**: Divide los datos en bloques y los distribuye entre discos.
- **Ventajas**: Máximo rendimiento (lectura/escritura acelerada).
- **Desventajas**: **Sin redundancia**. Si un disco falla, pierdes todos los datos.
- **Uso ideal**: Edición de video, caché de aplicaciones (donde la velocidad es clave).

### **RAID 1 (Mirroring)**
- **Cómo funciona**: Duplica los datos en todos los discos (espejo).
- **Ventajas**: **Redundancia total**. Si un disco falla, el otro tiene una copia.
- **Desventajas**: Capacidad útil = tamaño de un solo disco (50% de overhead).
- **Uso ideal**: Almacenamiento crítico (ej.: sistemas operativos, bases de datos).

### **RAID 5 (Striping + Paridad Distribuida)**
- **Cómo funciona**: Bloques de datos + paridad distribuida en todos los discos. Requiere **mínimo 3 discos**.
- **Ventajas**: **Redundancia con buena capacidad** (solo pierdes 1 disco de espacio). Buen equilibrio rendimiento/seguridad.
- **Desventajas**: Escritura más lenta por cálculo de paridad. Riesgo durante reconstrucción (en discos grandes).
- **Uso ideal**: Servidores de archivos, NAS empresariales.

### **RAID 6 (Striping + Doble Paridad)**
- **Cómo funciona**: Como RAID 5, pero con **2 discos de paridad** (mínimo 4 discos).
- **Ventajas**: Tolera fallos de **2 discos simultáneos**.
- **Desventajas**: Mayor overhead de capacidad y menor rendimiento en escritura.
- **Uso ideal**: Entornos con alta disponibilidad (ej.: centros de datos).

### **RAID 10 (1+0: Espejo + Striping)**
- **Cómo funciona**: Combina RAID 1 y RAID 0. Mínimo **4 discos** (2 pares en espejo, luego striping).
- **Ventajas**: Alto rendimiento + tolerancia a fallos (puede perder 1 disco por par).
- **Desventajas**: Coste (50% de capacidad útil).
- **Uso ideal**: Bases de datos críticas, virtualización.

---

## **3. RAID Anidados (Combinados)**
- **RAID 50 (5+0)**: Combina RAID 5 en grupos con striping. Mejor rendimiento que RAID 5.
- **RAID 60 (6+0)**: Similar a RAID 50, pero con RAID 6 como base. Mayor tolerancia a fallos.

---

## **4. ¿Hardware vs Software RAID?**
- **Hardware RAID**: Controladora dedicada (ej.: LSI, Adaptec). Mejor rendimiento y soporte para niveles complejos (5, 6, etc.).
- **Software RAID**: Gestionado por el SO (ej.: mdadm en Linux, Storage Spaces en Windows). Más económico pero consume CPU.

---

## **5. Conceptos Clave para Expertos**
- **Hot Spare**: Disco de reserva que se activa automáticamente al fallar otro.
- **BBU (Battery Backup Unit)**: En RAID hardware, protege la caché en cortes de energía.
- **Reconstrucción**: Proceso de restaurar datos después de reemplazar un disco fallado.
- **Tiempo de MTBF**: Estimación de vida útil de un array RAID.
- **ZFS y RAID-Z**: Sistema de archivos avanzado (usado en FreeNAS) que mejora RAID tradicional con corrección de errores.

---

## **6. ¿Cuál Elegir?**
| Escenario               | RAID Recomendado |
|-------------------------|------------------|
| Máxima velocidad        | RAID 0           |
| Copia de seguridad      | RAID 1           |
| Balance rendimiento/seguridad | RAID 5           |
| Entornos críticos       | RAID 6 o 10      |
| Virtualización          | RAID 10          |

---

## **7. Herramientas para Gestionar RAID**
- **Linux**: `mdadm`, `lsblk`, `smartctl`.
- **Windows**: Administración de discos, Storage Spaces.
- **Monitorización**: `MegaRAID Storage Manager` (para hardware RAID).

---

## **8. Mitos y Realidades**
- ❌ *"RAID reemplaza backups"*: Falso. RAID protege contra fallos de hardware, no contra ransomware o errores humanos.
- ✅ *"RAID 5 ya no es seguro"*: Discutible. En discos >4TB, la reconstrucción puede fallar (mejor RAID 6).

