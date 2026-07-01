### 💻 Software Didáctico y Herramientas Recomendadas

1. **Logisim / Logisim-Evolution:** Ideal para los primeros módulos. Permite dibujar circuitos lógicos, colocar compuertas, probar tablas de verdad en tiempo real y construir componentes complejos (como sumadores o Flip-Flops) de forma visual.
2. **Deeds (Digital Electronics Education and Design Suite):** Excelente software didáctico para simular tanto circuitos combinacionales como secuenciales, y permite introducir conceptos de autómatas y diagramas de transición.
3. 
**Simulador ABACUS / MIPS / SASM:** Para los módulos avanzados de arquitectura, un simulador visual que muestre la ruta de datos (buses, registros y UCP) y cómo se mueven los bits paso a paso al ejecutar una instrucción (como la suma) es fundamental.



---

### 🎬 Estructura de la Serie de Videos (Capítulos de 20 min)

#### 📦 MÓDULO 1: Fundamentos y Codificación (Capítulos 1 y 2)

Este bloque es la base matemática y teórica de cómo la información entra a la máquina.

* **Capítulo 1: El Lenguaje de la Máquina y los Sistemas de Numeración (20 min)**
* 
**Contenido:** Concepto de sistema digital y procesamiento de datos. Conversión de bases (Binario, Decimal, Base M). Representación con signo (Coma Fija y Coma Flotante).


* 
**Estrategia didáctica/Ejemplos:** Usar pizarrón digital para resolver paso a paso la conversión del número decimal $177$ a base 4 ($2301_4$) y la normalización en binario de una mantisa.




* **Capítulo 2: Códigos de Entrada y Detección de Errores (20 min)**
* 
**Contenido:** Agrupamientos binarios (Bit, Byte, Palabra). Códigos ponderados (BCD, AIKEN) y no ponderados (Gray). Introducción a ASCII y EBCDIC. Códigos redundantes (Paridad y el código corrector de Hamming).


* 
**Estrategia didáctica/Ejemplos:** Mostrar cómo el número decimal $70922$ se transforma de manera diferente en BCD y en exceso de 3. Utilizar una planilla interactiva para simular cómo el receptor calcula los bits de control en Hamming para detectar y corregir la posición exacta de un bit erróneo.





#### 🔌 MÓDULO 2: Circuitos Lógicos Combinacionales (Capítulos 3 y 4)

*Aquí pasamos de la matemática pura a la implementación con compuertas lógicas usando **Logisim**.*

* **Capítulo 3: Álgebra de Boole y Minimización de Circuitos (20 min)**
* 
**Contenido:** Variables, funciones lógicas y tablas de verdad. Funciones básicas (AND, OR, NOT) y OR Exclusivo (XOR). Formas canónicas (Minitérminos y Maxitérminos). Simplificación por Teoremas y Mapas de Karnaugh.


* 
**Estrategia didáctica/Ejemplos:** Diseñar en Logisim un circuito con una tabla de verdad aleatoria. Demostrar el "Valor Económico de la Simplificación" mostrando en pantalla cómo un circuito gigante de 3 variables se reduce a una expresión mínima como $F = \bar{B}\bar{C} + \dots$ usando el mapa de Karnaugh.




* **Capítulo 4: Operadores Aritméticos Combinacionales (20 min)**
* 
**Contenido:** El Semisumador (Half-Adder) y Sumador Completo (Full-Adder). El Sumador en Paralelo vs. Sumador en Serie (análisis del retardo). Semisustractor y Sustractor Completo. Matrices de codificación y decodificación.


* 
**Estrategia didáctica/Ejemplos:** Construir en vivo en Logisim un sumador completo uniendo dos Half-Adders y una compuerta OR. Simular una matriz rectangular de decodificación de 4 bits para activar salidas del 0 al 15.





#### 🔄 MÓDULO 3: Circuitos Secuenciales y Memoria (Capítulos 5 y 6)

Introducción del concepto del tiempo y el almacenamiento de datos.

* **Capítulo 5: El Tiempo en los Circuitos: Biestables y Autómatas (20 min)**
* 
**Contenido:** Circuitos combinacionales vs. secuenciales. Concepto de Autómata Finito (Estados internos, funciones de transición y diagramas de estado). Elementos de memoria: Flip-Flops (RS, JK, D, T y Maestro-Esclavo). Componentes complementarios: Monoestable y Astable.


* 
**Estrategia didáctica/Ejemplos:** Usar **Deeds** o Logisim para armar un Flip-Flop RS síncrono con compuertas NAND. Mostrar interactivamente en un diagrama de transición cómo un pulso de reloj hace cambiar de estado a un Flip-Flop JK cuando las entradas son $J=1, K=1$ (complementación).




* **Capítulo 6: Registros, Contadores y Organización de la Memoria Central (20 min)**
* 
**Contenido:** Operaciones sobre registros (carga, transferencia y desplazamiento). Contadores binarios. Introducción a la Memoria Central (RAM y ROM). Estructuras de selección y direccionamiento: Organizaciones 2D, 3D y 2.5D.


* 
**Estrategia didáctica/Ejemplos:** Simular en software un registro acumulador de 4 bits funcionando en conjunto con líneas de Bus. Explicar de manera gráfica la diferencia entre cómo se lee/escribe en una celda SRAM (2D) frente a una DRAM de corrientes coincidentes (3D).





#### 🧠 MÓDULO 4: Arquitectura del Procesador y Ejecución (Capítulos 7, 8 y 9)

El núcleo de la materia: la integración de todos los componentes bajo el modelo Von Neumann.

* **Capítulo 7: La Arquitectura Von Neumann y el Modelo ABACUS (20 min)**
* 
**Contenido:** La revolución de Von Neumann: programa registrado y ruptura de secuencia. Estructura de la UCP (Unidad de Control y ALU). Anatomía de la máquina ABACUS: registros (S, P, M, RI con CO y D, AC) y Buses de comunicación (Bus M y Bus S).


* 
**Estrategia didáctica/Ejemplos:** Utilizar un diagrama interactivo o simulador de arquitectura para mostrar los "bloques" del procesador. Mostrar visualmente cómo el Contador de Programa ($P$) envía la dirección al registro de selección ($S$) para iniciar la búsqueda de una instrucción.




* **Capítulo 8: Anatomía de una Instrucción: El Ciclo de la Suma en ABACUS (20 min)**
* 
**Contenido:** El ciclo de instrucción en sus 4 fases fundamentales: Búsqueda de instrucción, Búsqueda de operando, Ejecución de la operación y Preparación de la próxima instrucción. Señales de gobierno e impulsos de reloj (cronograma de la instrucción).


* **Estrategia didáctica/Ejemplos:** Este capítulo es un **caso de estudio práctico continuo**. Se explicará paso a paso cómo se ejecuta la instrucción `SUMA`. Veremos en pantalla las señales de nivel y de muestreo abrir y cerrar las compuertas de los registros interconectados (ej. activación de $SRP$, $ENS$, $LEC$, $SRM$, $ENI$, hasta llegar al impulso $EAC$ que guarda el resultado final en el Acumulador).




* **Capítulo 9: Operaciones Avanzadas en la ALU: Multiplicación y División (20 min)**
* 
**Contenido:** Multiplicación secuencial por suma y desplazamiento (uso del registro Multiplicador-Cociente MC y resultado en doble longitud). Multiplicación celular en paralelo. División secuencial por sustracción y desplazamiento. Métodos alternativos para abaratar costos: División con y sin restauración. Detección de desbordamiento (Overflow) en complemento a 2.


* 
**Estrategia didáctica/Ejemplos:** Desarrollar un ejemplo numérico animado siguiendo paso a paso el algoritmo del multiplicador secuencial, mostrando cómo cambia el bit $MC_0$ y cómo se desplaza el conjunto $AC-MC$. Explicar la regla del Overflow mediante un circuito XOR conectado a los acarreos del bit de signo.





#### 🔌 MÓDULO 5: El Entorno del Procesador y Tendencias Modernas (Capítulo 10)

*El cierre de la serie para conectar el procesador con el mundo exterior.*

* **Capítulo 10: Jerarquía de Memoria, Secuenciadores y Filosofías CISC vs. RISC (20 min)**
* 
**Contenido:** Por qué es necesaria una jerarquía de memoria (Costo, velocidad y capacidad). Niveles de caché (L1 y L2) y memoria secundaria. Secuenciadores cableados frente a microprogramados (Modelo de Wilkes). Comparativa de filosofías de diseño: CISC vs. RISC (estudio del microcontrolador PIC como arquitectura RISC/Harvard).


* 
**Estrategia didáctica/Ejemplos:** Presentar un gráfico animado de la pirámide de memoria y ejemplificar el comportamiento de la caché cuando la CPU pide un dato que no está mapeado originalmente en ella. Concluir el video contrastando el formato variable y complejo de instrucciones en sistemas CISC frente al pipeline eficiente de un ciclo por instrucción de los procesadores RISC modernos.





---

### ⏱️ Estructura del Tiempo Recomendada Dentro de Cada Video (Bloques de 20 min):

* **00:00 - 02:00 (2 min):** *Introducción y El Problema.* Planteo de qué necesidad de cómputo o comunicación vamos a resolver hoy.
* 
**02:00 - 08:00 (6 min):** *Desarrollo Teórico Base.* Explicación conceptual apoyada en los apuntes de la materia.


* 
**08:00 - 17:00 (9 min):** *Práctica y Software Didáctico.* Bloque central donde se abre **Logisim**, **Deeds** o el simulador de arquitectura y se muestra el ejemplo funcionando paso a paso.


* **17:00 - 20:00 (3 min):** *Resumen y Cierre.* Repaso de los conceptos clave y un gancho (*cliffhanger*) conectando con el tema del próximo capítulo.
