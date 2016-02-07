<?php
/**
 * Project: StartSSL API
 * By: D. van Gorkum <djvg@djvg.net>
 * Date: 29-Jan-16
 * Time: 22:00
 */
require_once("startssl.class.php");

// EXMAPLES //
// Start the StartSSL API, 3rd arg is password for private key and 4th if you want to see logging.
$startSSL = new StartSSL("crt.pem", "key.pem", NULL, TRUE);

// Requst a new certificate
// NOTE: This will take care of creating a PK/CSR and verifiying the domains BUT you still need to save your PK somewhere to use it.
var_dump($startSSL->newCertificate(array("domain.com", "www.domain.com", "*.domain.com")));

// Get ALL certficates in your account.
var_dump($startSSL->getCertificates());

// Get PEM encoded certficate for "domain.com".
var_dump($startSSL->getCertificatePem("domain.com"));

// Get certficate in ZIP package for "domain.com".
$zipPackage = $startSSL->getCertificateZip("domain.com");
// You can write $zipPackage to a file or do something else with it.

// Get validated domains.
var_dump($startSSL->getValidatedDomains());

// Verify domains with StartSSL.
var_dump($startSSL->verifyDomains(array("domain.com", "www.domain.com", "*.domain.com")));

// Create new Private key
var_dump($startSSL->newPrivateKey());

// Get Private key
var_dump($startSSL->getPrivateKey());

// Create new CSR.
var_dump($startSSL->newCsr());

// Get CSR.
var_dump($startSSL->getCsr());

// Verify CSR with StartSSL.
var_dump($startSSL->verifyCsr());