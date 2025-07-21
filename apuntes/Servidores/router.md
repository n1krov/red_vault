## 📡 ¿Qué es un **router**?

Un **router** (enrutador) es un **dispositivo de red que se encarga de enviar paquetes de datos entre distintas redes**. Su función principal es **decidir por dónde va cada paquete** para llegar a su destino, usando **tablas de enrutamiento**.

---

### 🧠 ¿Qué hace un router?

- 📍 Conecta **redes diferentes** (ejemplo: LAN a Internet).
    
- 📦 Toma un paquete de datos y **elige la mejor ruta** para enviarlo.
    
- 🔐 Puede incluir funciones de seguridad: NAT, firewall, VPN.
    
- 🌐 Se encarga del **tráfico entrante y saliente** desde tu red hacia el exterior.
    

---

### 🧭 Tipos de routers que podés encontrar

|Tipo|Dónde se usa|Función principal|
|---|---|---|
|**Router doméstico**|En casas / pymes|Conecta una red local al ISP|
|**Router de borde**|En datacenters / empresas grandes|Conecta la red interna a Internet|
|**Router core**|En el backbone de ISPs|Maneja tráfico masivo de red|
|**Router virtualizado**|En la nube o redes SDN|Corre en software, no hardware dedicado|

---

### 🛠️ Funciones importantes de un router empresarial o de datacenter:

- **NAT (Network Address Translation)**: Traduce IPs privadas a públicas y viceversa.
    
- **Routing dinámico**: Protocolos como BGP, OSPF, EIGRP, etc.
    
- **QoS (Quality of Service)**: Prioriza cierto tipo de tráfico.
    
- **VPN (Red privada virtual)**: Túneles cifrados entre sedes o usuarios.
    
- **ACL (Access Control Lists)**: Reglas para permitir/bloquear tráfico.
    

---

### 🔗 ¿Dónde se ubica un router en un datacenter?

En un diagrama de red, suele estar **entre el firewall y el proveedor de Internet (ISP)**.

```text
[LAN / Servidores] --> [Firewall] --> [Router de Borde] --> [ISP / Internet]
```

En redes grandes también se usa una jerarquía:

```text
[Router de Core] --> [Router de Distribución] --> [Router de Acceso]
```

---

### 🎛️ Ejemplos de routers reales

- **Cisco ASR / ISR**
    
- **Juniper MX**
    
- **MikroTik**
    
- **Ubiquiti EdgeRouter**
    
- **VyOS** (router virtualizado en Linux)
    

---

### 🧩 Diferencia con otros dispositivos

|Dispositivo|Qué hace|
|---|---|
|**Router**|Enruta entre redes|
|**Switch**|Conecta dispositivos dentro de una misma red|
|**Firewall**|Filtra tráfico según reglas|
|**Modem**|Convierte señal analógica ↔ digital|


[[fundamento de servidores]]