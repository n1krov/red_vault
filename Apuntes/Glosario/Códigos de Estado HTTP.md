
Los códigos de estado HTTP son respuestas numéricas que indican el resultado de una solicitud HTTP. Se dividen en cinco categorías principales:

---

## **1xx: Respuestas Informativas**

| Código | Nombre                          | Descripción                                                                 |
|--------|---------------------------------|-----------------------------------------------------------------------------|
| 100    | Continue                        | La solicitud inicial ha sido recibida y el cliente debe continuar.          |
| 101    | Switching Protocols             | El servidor acepta el cambio de protocolo solicitado por el cliente.        |
| 102    | Processing                      | El servidor está procesando la solicitud, pero aún no hay respuesta.        |
| 103    | Early Hints                     | Se envían algunos encabezados antes de la respuesta final.                  |

---

## **2xx: Respuestas Exitosas**

| Código | Nombre                          | Descripción                                                                 |
|--------|---------------------------------|-----------------------------------------------------------------------------|
| 200    | OK                              | La solicitud ha sido exitosa.                                               |
| 201    | Created                         | La solicitud ha sido exitosa y se ha creado un nuevo recurso.               |
| 202    | Accepted                        | La solicitud ha sido aceptada, pero aún no se ha procesado.                 |
| 203    | Non-Authoritative Information   | La información devuelta no es la oficial del servidor.                      |
| 204    | No Content                      | La solicitud ha sido exitosa, pero no hay contenido para devolver.          |
| 205    | Reset Content                   | La solicitud ha sido exitosa, y el cliente debe resetear la vista.          |
| 206    | Partial Content                 | El servidor está devolviendo solo una parte del recurso solicitado.         |
| 207    | Multi-Status                    | La respuesta contiene múltiples códigos de estado para operaciones múltiples.|
| 208    | Already Reported                | Los miembros de un DAV binding ya han sido enumerados previamente.          |
| 226    | IM Used                         | El servidor ha cumplido una solicitud para el recurso.                      |

---

## **3xx: Redirecciones**

| Código | Nombre                          | Descripción                                                                 |
|--------|---------------------------------|-----------------------------------------------------------------------------|
| 300    | Multiple Choices                | Hay múltiples opciones para el recurso solicitado.                          |
| 301    | Moved Permanently               | El recurso ha sido movido permanentemente a una nueva URL.                  |
| 302    | Found                           | El recurso ha sido movido temporalmente a una nueva URL.                    |
| 303    | See Other                       | La respuesta a la solicitud puede ser encontrada en otra URL.               |
| 304    | Not Modified                    | El recurso no ha sido modificado desde la última solicitud.                 |
| 305    | Use Proxy                       | El recurso debe ser accedido a través de un proxy.                          |
| 307    | Temporary Redirect              | El recurso ha sido movido temporalmente a una nueva URL.                    |
| 308    | Permanent Redirect              | El recurso ha sido movido permanentemente a una nueva URL.                  |

---

## **4xx: Errores del Cliente**

| Código | Nombre                          | Descripción                                                                 |
|--------|---------------------------------|-----------------------------------------------------------------------------|
| 400    | Bad Request                     | La solicitud no pudo ser entendida por el servidor.                         |
| 401    | Unauthorized                    | Se requiere autenticación para acceder al recurso.                          |
| 402    | Payment Required                | Reservado para uso futuro.                                                  |
| 403    | Forbidden                       | El servidor entiende la solicitud, pero se niega a cumplirla.               |
| 404    | Not Found                       | El recurso solicitado no fue encontrado.                                    |
| 405    | Method Not Allowed              | El método HTTP no está permitido para el recurso solicitado.                |
| 406    | Not Acceptable                  | El servidor no puede producir una respuesta acorde a los encabezados aceptados.|
| 407    | Proxy Authentication Required   | Se requiere autenticación con el proxy.                                     |
| 408    | Request Timeout                 | El servidor ha agotado el tiempo de espera para la solicitud.               |
| 409    | Conflict                        | Conflicto en la solicitud con el estado actual del recurso.                 |
| 410    | Gone                            | El recurso solicitado ya no está disponible y no se proporcionará redirección.|
| 411    | Length Required                 | El servidor requiere una cabecera `Content-Length` en la solicitud.         |
| 412    | Precondition Failed             | Una condición previa en la solicitud ha fallado.                            |
| 413    | Payload Too Large               | La solicitud es más grande de lo que el servidor está dispuesto a procesar. |
| 414    | URI Too Long                    | La URI solicitada es más larga de lo que el servidor está dispuesto a interpretar.|
| 415    | Unsupported Media Type          | El formato de los datos no es soportado por el recurso solicitado.          |
| 416    | Range Not Satisfiable           | El rango solicitado no es satisfacible.                                     |
| 417    | Expectation Failed              | La expectativa indicada en la cabecera `Expect` no pudo ser cumplida.       |
| 418    | I'm a teapot                    | (Broma) El servidor es una tetera y no puede preparar café.                 |
| 421    | Misdirected Request             | La solicitud fue dirigida a un servidor que no puede producir una respuesta. |
| 422    | Unprocessable Entity            | La solicitud está bien formada pero no pudo ser seguida debido a errores semánticos.|
| 423    | Locked                          | El recurso al que se está accediendo está bloqueado.                        |
| 424    | Failed Dependency               | La solicitud falló debido a una dependencia fallida.                        |
| 425    | Too Early                       | El servidor no está dispuesto a arriesgarse a procesar una solicitud que podría ser repetida.|
| 426    | Upgrade Required                | El cliente debe cambiar a un protocolo diferente.                           |
| 428    | Precondition Required           | El servidor requiere que la solicitud sea condicional.                      |
| 429    | Too Many Requests               | El usuario ha enviado demasiadas solicitudes en un período de tiempo.       |
| 431    | Request Header Fields Too Large | Los campos de la cabecera de la solicitud son demasiado grandes.            |
| 451    | Unavailable For Legal Reasons   | El recurso no está disponible por razones legales.                          |

---

## **5xx: Errores del Servidor**

| Código | Nombre                          | Descripción                                                                 |
|--------|---------------------------------|-----------------------------------------------------------------------------|
| 500    | Internal Server Error           | El servidor encontró una condición inesperada que le impidió cumplir la solicitud.|
| 501    | Not Implemented                 | El servidor no soporta la funcionalidad requerida para cumplir la solicitud.|
| 502    | Bad Gateway                     | El servidor actuando como gateway recibió una respuesta inválida.           |
| 503    | Service Unavailable             | El servidor no está disponible temporalmente.                               |
| 504    | Gateway Timeout                 | El servidor actuando como gateway no recibió una respuesta a tiempo.        |
| 505    | HTTP Version Not Supported      | El servidor no soporta la versión del protocolo HTTP utilizada en la solicitud.|
| 506    | Variant Also Negotiates         | El servidor tiene un error de configuración interna.                        |
| 507    | Insufficient Storage            | El servidor no puede almacenar la representación necesaria para completar la solicitud.|
| 508    | Loop Detected                   | El servidor detectó un bucle infinito mientras procesaba la solicitud.      |
| 510    | Not Extended                    | Se necesitan más extensiones para cumplir la solicitud.                     |
| 511    | Network Authentication Required | El cliente necesita autenticarse para obtener acceso a la red.              |

---

### **Resumen**

- **1xx**: Respuestas informativas.
- **2xx**: Respuestas exitosas.
- **3xx**: Redirecciones.
- **4xx**: Errores del cliente.
- **5xx**: Errores del servidor.

---

### **Consejo Final**

Conocer los códigos de estado HTTP es esencial para diagnosticar problemas en aplicaciones web y APIs. ¡Guarda este listado en tu Obsidian para tenerlo siempre a mano!

[[glosario]]