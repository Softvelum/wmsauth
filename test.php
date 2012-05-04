<?php
$today = gmdate("n/j/Y g:i:s A");

$initial_url = "mms://w2008sp2x64.wmspanel.com/u2";

$url_with_servertime = $initial_url ."?server_time=" . $today;

$ip = "95.154.108.229";
$key = "defaultpassword";

$validminutes = 5;

$str2hash = $ip . $key . $today . $validminutes;

$md5raw = md5($str2hash, true);

$base64hash = base64_encode($md5raw);

$signedurl = $url_with_servertime ."&hash_value=" . $base64hash;

$signedurlwithvalidinterval = $signedurl . "&validminutes=$validminutes";

echo $signedurlwithvalidinterval . "\n";
?>
