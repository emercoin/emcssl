<?php
// *** emcSSL demo ***
// Don't use external modules
// Can work with remote EMC-wallet, all data exchange by JSON only
//
// Program prints (echoes) parameter of client's emcSSL certificate
// and InfoCard fields


// show errors right in browser
error_reporting(E_ALL);
ini_set('display_errors', 'on');

// Export here connect variable, like:
// $emcCONNECT = "http://user:secret_pass@localhost:8775";
include("config-lite.php");

//------------------------------------------------------------------------------
// There will be unpacked infocard
$emc_infocard = array();

// Infocard limit
$emc_infocard_limit = 20;

# Need create this directory, and allow read for www-owner with command like
$emc_infocard_cache_path = "/var/tmp/infocard";

//------------------------------------------------------------------------------
// Performs name_show NVS-request to EMC wallet
function emcssl_NVS_req($params) {
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
    throw new Exception('emcssl_NVS_req: Unable to connect to EMC-wallet');

  $rc = json_decode(stream_get_contents($fp), true);
  $er = $rc['error'];
  if(!is_null($er)) 
    throw new Exception('emcssl_NVS_req: Response error: ' . $er);

  return $rc['result'];
} // emcssl_NVS
 
//------------------------------------------------------------------------------
// Returns text string: ['$' . clients EMC address] if emcssl certificate passed check OK
// EMC-address started with 'E/e' letters
// or an error text, if validating fails
// Useful env values
//   $_SERVER['SSL_CLIENT_M_SERIAL']	- Unique client's serial number (key)
//   $_SERVER['SSL_CLIENT_S_DN_Email']	- Client's e-mail
//   $_SERVER['SSL_CLIENT_S_DN_UID']	- infocard reference
// Don't forget setup: SSLOptions +ExportCertData
function emcssl_validate() {
  try {
    if(!array_key_exists('SSL_CLIENT_CERT', $_SERVER))
      return "No certificate presented, or missing flag +ExportCertData";

    if(!array_key_exists('SSL_CLIENT_I_DN_UID', $_SERVER))
      return "This certificane is not belong to any cryptocurrency";

    if($_SERVER['SSL_CLIENT_I_DN_UID'] != 'EMC')
      return "Wrong blockchain currency - this is not EmerCoin blockchain certificate";

    // Generate search key, and retrieve NVS-value 
    $key = str_pad(strtolower($_SERVER['SSL_CLIENT_M_SERIAL']), 16, 0, STR_PAD_LEFT);
    if($key[0] == '0') 
      return "Wrong serial number - must not start from zero";
    $key = "ssl:" . $key;
    $nvs = emcssl_NVS_req(array($key));
    if($nvs['expires_in'] <= 0)
      return "NVS record expired, and is not trustable";

    // Compute certificate fingerprint, using algo, defined in the NVS value
    list($algo, $emc_fp) = explode('=', $nvs['value']);
    $crt_fp = hash($algo, 
                   base64_decode(
                     preg_replace('/\-+BEGIN CERTIFICATE\-+|-+END CERTIFICATE\-+|\n|\r/',
                       '', $_SERVER['SSL_CLIENT_CERT'])));

    return ($emc_fp == $crt_fp)? '$' . $nvs['address'] : "False certificate provided";

  } catch(Exception $e) {
    return "Cannot extract from NVS key=$key"; // Any mmcFE error - validation fails
  }
} // emcssl_validate


//------------------------------------------------------------------------------
// Populate global array $emc_infocard
// 
// Before InfoCard usage:
//   mkdir /var/tmp/infocard/
//   chown www-data /var/tmp/infocard/
//

function emcssl_infocard($ic_ref) {
  global $emc_infocard_cache_path, $emc_infocard_limit;

  // echo "Called emcssl_infocard($ic_ref)\n";
  if(--$emc_infocard_limit < 0)
    return "Too long InfoCard reference chain";

  // Remove possible hazardous symbols, for preserve shell injection
  list($service, $key, $passwd) = 
    explode(':', preg_replace('/[^0-9A-Za-z_:]/', '', $ic_ref));

  if($service != "info")
    return "Unsupported InfoCard service type: $service\n";

  if(!isset($passwd))
    return "Wrong InfoCard link format - missing password";

  $cached_path = "$emc_infocard_cache_path/$key";

  // If cached file too old (10+min) or non exist - read from NVS and create it
  if(!file_exists($cached_path) || time() - filemtime($cached_path) > 600) {
    try {
      $nvs = emcssl_NVS_req(array("info:$key"));
       if($nvs['expires_in'] <= 0) {
         touch($cached_path);
         return "NVS record expired, and is not trustable";
       }
       $fh = popen("openssl aes-256-cbc -d -pass pass:$passwd | zcat > $cached_path", "wb");
       # PHP automatically treadt binary as UTF-8, and convert to unicode, so need decode back
       fwrite($fh, utf8_decode($nvs['value']));
       pclose($fh);
    } catch(Exception $e) {
      touch($cached_path);
      return "Unable fetch from NVS value for key=info:$key";
    } 
  } // fetch infocard to the cache 

  $fh = fopen($cached_path, "r");
  
  // Read InfoCard file, line by line
  $k     = "";
  $old_k = "";
  $loc_arr = array();
  $tpr = '_hash_' . getmypid() . '_';

  while(($buffer = fgets($fh, 4096)) !== false) {
    #echo "Buf=$buffer";
    preg_match('/^(\S+)?(\s+)(.+)?/', $buffer, $matches);
    // print_r($matches);
    if(isset($matches[1]) && !empty($matches[1]))
      $k = $matches[1];
    $v = "";
    if(isset($matches[3])) {
      $v = preg_replace('/\\\#/', $tpr, $matches[3]);
      $v = preg_replace('/\s*\#.*/', '', $v);
      $v = preg_replace("/$tpr/", '#', $v);
    }
    if(!empty($k) && !empty($v)) {
      if($k != $old_k) {
        // merge loc_arr to  $emc_infocard
        emcssl__merge($old_k, $loc_arr);
        $loc_arr = array();
      }
      array_push($loc_arr, $v);
      $old_k = $k;
    }
  } // while
  fclose($fh);

  // merge last array, if exist
  emcssl__merge($k, $loc_arr);
  return '$';
} // emcssl_infocard

//------------------------------------------------------------------------------
function emcssl__merge($k, $loc_arr) {
  global  $emc_infocard;
  if(empty($k))
    return;
  //echo "Called merge for [$k]\n";
  //print_r($loc_arr);
  if($k == 'Import') {
  foreach ($loc_arr as $ic_ref)
    emcssl_infocard($ic_ref);
  } else {
    preg_match('/([+]?)([^+]+)([+]?)/', $k, $matches);
    if(!isset($matches[2]) || empty($matches[2]))
      return; // Garbage key

    $q1 = isset($matches[1]) && !empty($matches[1]);
    $q3 = isset($matches[3]) && !empty($matches[3]);
    $k  = $matches[2];
 
    if(!$q1 && !$q3) {
      // key
      $emc_infocard[$k] = $loc_arr;
    }
    if($q1 && !$q3) {
      // +key
      $emc_infocard[$k] = isset($emc_infocard[$k])? 
        array_merge($emc_infocard[$k], $loc_arr) : $loc_arr;
    }
    if(!$q1 && $q3) {
      // key+
      $emc_infocard[$k] = isset($emc_infocard[$k])?
        array_merge($loc_arr, $emc_infocard[$k]) : $loc_arr;
    }
  }
  // echo "========================\n";
} // emcssl__merge


//------------------------------------------------------------------------------
// Main program here

function envprint($txt, $key) {
  echo "\t$txt: ";
  if(array_key_exists($key, $_SERVER)) { 
    echo htmlspecialchars($_SERVER[$key]);
  } else { 
    echo "&lt;Omitted&gt;";
  }
  echo "\n";
} // envprint

echo "<pre>\n";

echo "pid=" . getmypid() . "\n\n";

// Print SSL-certificate fields
if(array_key_exists('SSL_CLIENT_CERT', $_SERVER)) {
  echo "main: SSL-certificate presented\n\n";
  envprint("SerialNo", 'SSL_CLIENT_M_SERIAL');
  envprint("Currency", 'SSL_CLIENT_I_DN_UID');
  envprint("CommName", 'SSL_CLIENT_S_DN_CN');
  envprint("e-Mail  ", 'SSL_CLIENT_S_DN_Email');
  envprint("InfoCard", 'SSL_CLIENT_S_DN_UID');
} else {
  echo "main: No SSL-certificate presented";
}

// Verify emcssl here
echo "\nemcssl_validate() RETURNED: " . emcssl_validate() . "\n\n";

if(array_key_exists('SSL_CLIENT_S_DN_UID', $_SERVER)) {
   $err = emcssl_infocard($_SERVER['SSL_CLIENT_S_DN_UID']);
   echo "+InfoCard presented: $err\n";
   echo htmlspecialchars(print_r($emc_infocard, 1));
} else {
  echo "-No InfoCard presented\n";
}


echo "------------------------------------------\n";
// This is just for testing, try to retrieve additional InfoCards
$emc_infocard = array();
$emc_infocard_limit = 20;

if(array_key_exists('Info', $_GET)) {
  echo "External infocard: " . $_GET['Info'] . "\n";
  emcssl_infocard($_GET['Info']);
  echo htmlspecialchars(print_r($emc_infocard, 1));
}
// echo "Connection is - " . $_SERVER['HTTPS'];

//echo phpinfo();
?>
