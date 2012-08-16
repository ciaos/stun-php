<?php

include_once("STUNClient.php");

//фа╠нsocketм╗пе╬╞╦Ф
error_reporting(E_ERROR);

$sc = new STUNClient();

//$sc->setServerAddr("stun.ekiga.net"); 
//$sc->setServerAddr("stun.iptel.org");
$sc->setServerAddr("stunserver.org");
$sc->createSocket();

print("NAT TYPE:" . $sc->natType2String($sc->getNatType()) ."\n");
print("MAPPED ADDRESS:" . $sc->getMappedAddr() . "\n");

?>