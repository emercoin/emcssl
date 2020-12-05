<?php
// *** emerSSL demo *** 
// Simple Nginx version, no InfoCard here
//
// Can work with remote EMC-wallet, all data exchange by JSON only
//
// Program prints (echoes) parameter of client's emcSSL certificate
//
// To successfully run, pass to php/fcgi certificate info, by set up 
// variables in the vhost config:
/*
        location ~ .php$ {
		fastcgi_param SSL_CLIENT_M_SERIAL    $ssl_client_serial;
		fastcgi_param SSL_CLIENT_CERT        $ssl_client_raw_cert;
		fastcgi_param SSL_S_DN               $ssl_client_s_dn;

                include fastcgi_params;
                fastcgi_pass 127.0.0.1:9000;
                fastcgi_intercept_errors on;
                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME $request_filename; # Or $document_root$fastcgi_script_name
        }
*/

// show errors right in browser
ini_set('display_errors', 'on');

// Export here connect variable, like:
// $emcCONNECT = "http://user:secret_pass@localhost:8775";
include("config-lite.php");

//------------------------------------------------------------------------------
// Performs name_show NVS-request to EMC wallet
function emerssl_NVS_req($params) {
  global $emcCONNECT;
  // Prepares the request
  $request = json_encode(array(
    'method' => 'name_show',
    'params' => $params,
    'id' => '1'
  ));
  // Prepare and performs the HTTP POST
  $opts = array ('http' => array (
    'method'  => 'POST',
    'header'  => 'Content-type: application/json',
    'content' => $request
  ));
  $fp = fopen($emcCONNECT, 'rb', false, stream_context_create($opts));
  if(!$fp) 
    throw new Exception('emerssl_NVS_req: Unable to connect to EMC-wallet');

  $rc = json_decode(stream_get_contents($fp), true);
  $er = $rc['error'];
  if(!is_null($er)) 
    throw new Exception('emerssl_NVS_req: Response error: ' . $er);

  return $rc['result'];
} // emerssl_NVS
 
//------------------------------------------------------------------------------
// Returns text string: ['$' . clients EMC address] if emerssl certificate passed check OK
// EMC-address started with 'E/e' letters
// or an error text, if validating fails

function emerssl_validate() {
  try {
    if(!array_key_exists('SSL_CLIENT_CERT', $_SERVER) || empty($_SERVER['SSL_CLIENT_CERT']))
      return "No certificate presented, or server misconfigured";

    // Generate search key, and retrieve NVS-value 
    $key = str_pad(strtolower($_SERVER['SSL_CLIENT_M_SERIAL']), 16, 0, STR_PAD_LEFT);
    if($key[0] == '0') 
      return "Wrong serial number - must not start from zero";
    $key = "ssl:" . $key;
    $nvs = emerssl_NVS_req(array($key));
    if($nvs['expires_in'] <= 0)
      return "NVS record expired, and is not trustable";

    // NVS lines; 1st contains hash_algo=hash_value
    $lines = explode(PHP_EOL, $nvs['value']);

    // Compute certificate fingerprint, using algo, defined in the NVS value
    list($algo, $emc_fp) = explode('=', $lines[0]);
    $crt_fp = hash($algo, 
                   base64_decode(
                     preg_replace('/\-+BEGIN CERTIFICATE\-+|-+END CERTIFICATE\-+|\n|\r/',
                       '', $_SERVER['SSL_CLIENT_CERT'])));

    return ($emc_fp == $crt_fp)? '$' . $nvs['address'] : "False certificate provided";

  } catch(Exception $e) {
    return "Cannot extract from NVS key=$key"; // Any mmcFE error - validation fails
  }
} // emerssl_validate

//------------------------------------------------------------------------------
// Main program here

echo "<pre>\n";
echo "pid=" . getmypid() . "\n\n";

// Print SSL-certificate fields
if(array_key_exists('SSL_CLIENT_CERT', $_SERVER) && !empty($_SERVER['SSL_CLIENT_CERT'])) {
  echo "main: SSL-certificate presented\n\n";
  echo "\tSerialNo => " . htmlspecialchars($_SERVER['SSL_CLIENT_M_SERIAL']) . "\n\n";
  foreach(explode(',', $_SERVER['SSL_S_DN']) as $pair) {
    $kv = explode('=', $pair);
    echo "\t" . htmlspecialchars($kv[0]) . " => " . htmlspecialchars($kv[1]) . "\n";
  }
} else {
  echo "main: No SSL-certificate presented";
}
// Verify emerssl here
echo "\nemerssl_validate() RETURNED: " . emerssl_validate() . "\n\n";

?>
