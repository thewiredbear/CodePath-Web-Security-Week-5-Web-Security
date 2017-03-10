<?php

// Symmetric Encryption

// Cipher method to use for symmetric encryption
const CIPHER_METHOD = 'AES-256-CBC';

function key_encrypt($string, $key, $cipher_method=CIPHER_METHOD) {
  //Key has to be of 32 bits
  $newKey = str_pad($key, 32, '*');

  //Work with initiliaztion vector to make the encryption stronger
  $iv_length = openssl_cipher_iv_length(CIPHER_METHOD);
  $iv = openssl_random_pseudo_bytes($iv_length);

  //Encrypt
  $encrypted = openssl_encrypt($string, CIPHER_METHOD, $newKey, OPENSSL_RAW_DATA, $iv);

  //put iv in front of string for decryption
  $message = $iv . $encrypted;
  
  return base64_encode($message);
}

function key_decrypt($string, $key, $cipher_method=CIPHER_METHOD) {
  //Key needs to be of 32 bits
  $newKey = str_pad($key, 32, '*');

  //Base 64 decode
  $iv_with_ciphertext = base64_decode($string);

  //Seperate initialization vector and encrypted text
  $iv_length = openssl_cipher_iv_length(CIPHER_METHOD);
  $iv = substr($iv_with_ciphertext, 0, $iv_length);
  $ciphertext = substr($iv_with_ciphertext, $iv_length);

  //Decrypt
  $plaintext = openssl_decrypt($ciphertext, CIPHER_METHOD, $newKey, OPENSSL_RAW_DATA, $iv);

  return $plaintext;
}


// Asymmetric Encryption / Public-Key Cryptography

// Cipher configuration to use for asymmetric encryption
const PUBLIC_KEY_CONFIG = array(
    "digest_alg" => "sha512",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
);

function generate_keys($config=PUBLIC_KEY_CONFIG) {
  $resource = openssl_pkey_new($config);

  //Extract the private key
  openssl_pkey_export($resource, $private_key);

  //Extract public key
  $key_details = openssl_pkey_get_details($resource);
  $public_key = $key_details["key"];

  return array('private' => $private_key, 'public' => $public_key);
}

function pkey_encrypt($string, $public_key) {
  openssl_public_encrypt($string, $encrypted, $public_key);

  //encode in base 64 to make contents viewable/shareable
  $message = base64_encode($encrypted);
  
  return $message;
}

function pkey_decrypt($string, $private_key) {
  //Decode from base64
  $ciphertext = base64_decode($string);

  openssl_private_decrypt($ciphertext, $decrypted, $private_key);

  return $decrypted;

}


// Digital signatures using public/private keys

function create_signature($data, $private_key) {
  // A-Za-z : ykMwnXKRVqheCFaxsSNDEOfzgTpYroJBmdIPitGbQUAcZuLjvlWH
  openssl_sign($data, $raw_signature, $private_key);

  $signature = base64_encode($raw_signature);
  return $signature;
}

function verify_signature($data, $signature, $public_key) {
  // Vigenère
  $raw_signature = base64_decode($signature);
  $result = openssl_verify($data, $raw_signature, $public_key);

  return $result;
}

?>
