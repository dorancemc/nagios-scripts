#!/usr/bin/php
<?php
// Creado por: Heberth Alexander Ardila Cuellar
//
// DMC Ingenieria
// Script verificar carga WHM
// instalar php-curl como dependencia
//

if ($argc != "6")
 {
   print "UNKNOWN - Los argumentos deben ser 5: servidor,usuario,clave,warning,critical";
   exit(3);
 }

 $whmserver = $argv[1];
 $whmusername = $argv[2];
 $whmpassword = $argv[3];
 $warning =  $argv[4];
 $critical = $argv[5];

//print ("Arg0: $argv[0]\n");
//print ("Server: $whmserver\n");
//print ("Usuario: $whmusername\n");
//print ("Pass: $whmpassword\n");

$query = "$whmserver:2087/json-api/loadavg?api.version=1";
$curl = curl_init();                                // Crea un objeto curl
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);       // Allow self-signed certs
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);       // Allow certs that do not match the hostname
curl_setopt($curl, CURLOPT_HEADER,0);               // Do not include header in output
curl_setopt($curl, CURLOPT_RETURNTRANSFER,1);       // Return contents of transfer on curl_exec
$header[0] = "Authorization: Basic " . base64_encode($whmusername.":".$whmpassword) . "\n\r";
curl_setopt($curl, CURLOPT_HTTPHEADER, $header);    // set the username and password
curl_setopt($curl, CURLOPT_URL, $query);            // execute the query
$result = curl_exec($curl);
if ($result == false) {
    error_log("curl_exec threw error \"" . curl_error($curl) . "\" for $query");
                                                    // log error if curl exec fails
}
curl_close($curl);

//print ("Result: $result");

//se filtra la cadena que entrega json
$preproce = explode('","', $result,3);
//se filtran las variables 1m 5m 15m
$preproce1 = explode('":"', $preproce[0],2);
$preproce2 = explode('":"', $preproce[1],2);
$preproce3 = explode('":"', $preproce[2],2);
// se almacena en el vector[0] el valor almacenado en vecto[1]
$preproce1[0] = $preproce1[1];
$preproce2[0] = $preproce2[1];
$preproce3[0] = $preproce3[1];
$preproce3[0] = substr($preproce3[0],0,-3);

// para tratar las variables, se convierten en float
$minuto1 = floatval($preproce1[0]);
$minuto5 = floatval($preproce2[0]);
$minuto15 = floatval($preproce3[0]);

// verifica las variables y su valor.
//print "minuto1: $minuto1\n";
//print "minutos5: $minuto5\n";
//print "minuto15: $minuto15\n";
 //print "arg1: $argv[1]";
// print $argv[$1];
// print $argv[$2];
// print $argv[$3];
// print $argv[$4];
// print $argv[$5];

switch ($minuto1) {
        case $minuto1 <= $warning:

        print "OK - $minuto1% es la carga de la cpu. | cpu=$minuto1%;$warning;$critical;0;100";
        exit(0);

        case (($minuto1  > $warning) && ($minuto1  < ($critical+1))):
        print "WARNING - $minuto1% es la carga de la cpu. | cpu=$minuto%;$warning;$critical;0;100";
        exit(1);

        case $minuto1 >= ($critical+1):
        print "CRITICAL - $minuto1% es la carga de la cpu. | cpu=$minuto%;$warning;$critical;0;100";
        exit(2);

        default:
        print "UNKNOWN - $minuto1% es la carga de la cpu. | cpu=$minuto%;$warning;$critical;0;100";
        exit(3);
}

?>

