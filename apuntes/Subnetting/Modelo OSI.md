### Objetivo
- Agrupar protocolos en capas
- Hay 7: aplicacion, presentacion, sesion, transporte, red, enlace de datos, fisica

### Fisica
- Son como las carreteras, los caminos que toman los paquetes para llegar a su destino
- Aqui entran los dispositivos y cables utilizados para la conexion

### Enlace de datos
- Actua como el inspector del paquete
- Verifica que el paquete este correcto y en caso de no estarlo corregirlo si es posible
- Controla el flujo de datos 

### Red
- Cuando la oficina de correo recibe tu paquete debe saber el destinatario y en caso de que haya un alto flujo de datos priorizara los paquetes mas importantes primero
- Es la capa del modelo mas activa
- Puede priorizar paquetes y hallar las rutas mas optimas

### Transporte
- Son los camiones que recorren las carreteras con los paquetes encima
- TCP y UDP
- Garantiza el envio y recepcion de los paquetes

### Sesion
- Encargado de comenzar y terminar la comunicacion entre dos hosts
- Hacen control de seguridad mediante logs

### Presentacion
- Traduce los datos para la siguiente capa
- Conversion de codigo a caracteres, compresion y cifrado de datos

### Aplicacion
- Consumision de los datos por fin
- HTTP, FTP, HTTPS, etc