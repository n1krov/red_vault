## 📡 Frecuencias en Wi-Fi: 2.4 GHz vs 5 GHz

---

### 🧬 ¿Qué es una frecuencia?

En Wi-Fi, la **frecuencia** indica cuántas veces una onda electromagnética vibra por segundo, y se mide en **GHz (gigahercios)**.

- **2.4 GHz = 2.400.000.000 ciclos por segundo**
    
- **5 GHz = 5.000.000.000 ciclos por segundo**
    

Más frecuencia → más velocidad de transmisión (potencial) pero **menos alcance**.

---

## ⚖️ Comparativa: 2.4 GHz vs 5 GHz

| Característica     | 2.4 GHz                                            | 5 GHz                                        |
| ------------------ | -------------------------------------------------- | -------------------------------------------- |
| 📶 Rango (alcance) | Mayor (penetra paredes)                            | Menor (se atenúa más fácilmente)             |
| 🚀 Velocidad       | Menor (hasta 600 Mbps con 802.11n)                 | Mayor (hasta varios Gbps con 802.11ac/ax)    |
| 📡 Canales         | 14 canales (solo 3 no se solapan)                  | +20 canales, muchos no solapados             |
| 🔀 Interferencias  | Alta (Bluetooth, microondas, etc.)                 | Baja (menos saturado)                        |
| 🎯 Uso típico      | Redes domésticas, IoT                              | Streaming, gaming, tráfico pesado            |
| 🌍 Compatibilidad  | Más universal (todos los dispositivos la soportan) | Algunos dispositivos antiguos no lo soportan |

---

## 📶 Canales Wi-Fi

### 🧩 2.4 GHz

- Tiene **14 canales**, pero **solo 3 no se solapan**: 1, 6 y 11.
    
- Cada canal ocupa **22 MHz** y están separados por 5 MHz → **interferencias inevitables** si no están bien elegidos.
    

**Ejemplo práctico**:

- Si 3 APs usan 1, 6 y 11: todo bien.
    
- Si dos usan el canal 6, hay colisión → pérdida de rendimiento.
    

> 🔧 _En pentesting, podés usar `airodump-ng` para ver los canales y detectar congestión/interferencias._

---

### 📡 5 GHz

- Tiene **23+ canales** no superpuestos (según región).
    
- Cada canal ocupa **20, 40, 80 o hasta 160 MHz**.
    
- Permite usar canales **anchos** sin interferencia → ideal para alta velocidad.
    

> 🔧 _Con `iw list` podés ver los canales disponibles y el ancho de banda soportado por tu interfaz._

---

## 🧠 ¿Qué implica esto en Red Team?

### 🕵️‍♂️ Como atacante:

#### ✅ Ventajas de atacar redes en 2.4 GHz:

- Mayor alcance: podés captar paquetes desde más lejos.
    
- Más dispositivos conectados (impresoras, cámaras, IoT, etc.).
    
- Más interferencias: ideal para ocultarte o inyectar ruido.
    

#### ⚠️ Desventajas:

- Más saturado → más tráfico no deseado.
    
- Menor velocidad de captura si hay mucho ruido.
    

---

#### ✅ Ventajas de atacar redes en 5 GHz:

- Más limpio: menos interferencias, tráfico más enfocado.
    
- Mayor velocidad: ideal para capturar handshakes más rápido.
    
- Canales menos monitoreados → evasión de detección.
    

#### ⚠️ Desventajas:

- Menor alcance → necesitás estar más cerca.
    
- No todos los adaptadores soportan inyección en 5 GHz.
    
- Algunos dispositivos no usan 5 GHz → red “vacía”.
    

---

## 🔥 Herramientas prácticas

|Herramienta|Uso|
|---|---|
|`airodump-ng`|Escanear redes, ver frecuencias|
|`iwconfig`|Ver frecuencia de tu interfaz|
|`iw wlan0 set freq`|Cambiar manualmente de canal|
|`hcxdumptool`|Capturar PMKID/handshake en ambas bandas|
|`airmon-ng`|Activar modo monitor y detectar banda|

---

## 🧪 Ejemplo real con `airodump-ng`:

```bash
airodump-ng wlan0mon
```

Verás algo como:

```
BSSID              PWR  Beacons  #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
C0:4A:00:12:34:56  -45       30     12    0   6  54e. WPA2 CCMP   PSK  Red_WIFI
D8:97:BA:00:AB:CD  -55       20     30    0  36 130   WPA2 CCMP   PSK  Red_5GHz
```

→ Canal 6 = 2.4 GHz  
→ Canal 36 = 5 GHz

---

## 🚀 Bonus: Band Steering

Muchos APs modernos usan “**band steering**”, donde un mismo SSID puede tener versiones en 2.4 y 5 GHz. El AP decide qué banda usar según la distancia del cliente.

> En Red Team: esto puede complicar tu ataque si solo estás escuchando una banda. **Escuchá ambas** para asegurarte.


---

[[index-wifi_security]]