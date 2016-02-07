<?php
/**
 * Project: StartSSL API
 * By: D. van Gorkum <djvg@djvg.net>
 * Date: 29-Jan-16
 * Time: 22:00
 */

class StartSSL {

    // Change me * no need to really change this because StartSSL will override everything *
    const OPENSSL_C     = "NL";
    const OPENSSL_ST    = "Noord-Holland";
    const OPENSSL_L     = "Amsterdam";
    const OPENSSL_O     = "Default organization";
    const OPENSSL_OU    = "Development";

    const VERSION = 1.0;
    private $cookie             = NULL;
    private $baseUrl            = "https://startssl.com/";
    private $authUrl            = "https://auth.startssl.com/";
    private $existingCerts      = array();
    private $validatedDomains   = array();
    private $privateKey         = NULL;
    private $csr                = NULL;
    private $logging            = false;

    // Options
    private $opensslSettings    = array("digest_alg" => "sha512", "private_key_bits" => 4096, "private_key_type" => OPENSSL_KEYTYPE_RSA);
    private $defaultDn          = array("countryName" => self::OPENSSL_C,"stateOrProvinceName" => self::OPENSSL_ST,"localityName" => self::OPENSSL_L,"organizationName" => self::OPENSSL_O,"organizationalUnitName" => self::OPENSSL_OU);

    function __construct($clientcrt, $clientkey, $clientpw = NULL, $logging = false) {
        if(is_bool($logging)) $this->logging = $logging;
        if(!openssl_pkey_get_private((is_file($clientkey) ? "file://".$clientkey : $clientkey), $clientpw))
            $this->log("Invalid client private key.", true);
        if(!openssl_pkey_get_public((is_file($clientcrt) ? "file://".$clientcrt : $clientcrt)))
            $this->log("Invalid client public key.", true);
        $this->log("Certificate / key looks valid.");
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);
        curl_setopt($handle, CURLOPT_USERAGENT, sprintf("StartSSL-PHP-API/%s", self::VERSION));
        curl_setopt($handle, CURLOPT_URL, $this->authUrl);
        curl_setopt($handle, CURLOPT_SSLCERT, $clientcrt);
        curl_setopt($handle, CURLOPT_SSLKEY, $clientkey);
        if(!is_null($clientpw))
            curl_setopt($handle, CURLOPT_SSLKEYPASSWD, $clientpw);
        $this->log("Authenticating...");
        $result = curl_exec($handle);
        preg_match('/^Set-Cookie: (MyStartSSLCookie=.*)$/m', $result, $matches);
        if(isset($matches[1])) {
            $this->cookie = $matches[1];
            $this->log("User authenticated.");
        }else
            $this->log("Unable to authenticate. Check certificate/key.", true);

    }

    function request($path) {
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_USERAGENT, sprintf("StartSSL-PHP-API/%s", self::VERSION));
        curl_setopt($handle, CURLOPT_URL, $this->baseUrl.$path);
        curl_setopt($handle, CURLOPT_COOKIE, $this->cookie);
        $this->log(sprintf("Send GET to %s.", $path));
        $result = curl_exec($handle);
        return ($result === false ? false : $result);
    }

    function post($path, $data) {
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_USERAGENT, sprintf("StartSSL-PHP-API/%s", self::VERSION));
        curl_setopt($handle, CURLOPT_URL, $this->baseUrl.$path);
        curl_setopt($handle, CURLOPT_COOKIE, $this->cookie);
        curl_setopt($handle, CURLOPT_POST, 1);
        curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
        $this->log(sprintf("Send POST to %s.", $path));
        $result = curl_exec($handle);
        return ($result === false ? false : $result);
    }

    function getCertificates() {
        $this->log("Getting all certificates.");
        $certs = json_decode($this->request("/ControlPanel/AjaxRequestGetSSLCert"));
        if($certs !== FALSE)
            foreach($certs as $cert)
                $this->existingCerts[$cert->CommonName]['id'] = $cert->_id;
        else
            return false;
        return $this->existingCerts;
    }

    function getValidatedDomains() {
        $this->log("Getting all validated domains.");
        $domains = json_decode($this->request("/ControlPanel/AjaxRequestGetAllDomainValis"));
        if($domains !== FALSE)
            foreach($domains as $domain)
                if($domain->Verified === "y" && !in_array($domain->Domain, $this->validatedDomains))
                    $this->validatedDomains[] = $domain->Domain;
        else
            return false;
        return $this->validatedDomains;
    }

    function getCertificatePem($commonName) {
        $this->log(sprintf("Getting PEM certificate for CN %s.", $commonName));
        if(empty($this->existingCerts))
            $this->getCertificates();
        if(!array_key_exists($commonName, $this->existingCerts)) {
            $this->log("No signed certificate found with this CN.");
            return false;
        }
        $cert = $this->request(sprintf("/CertList/WriteCert?orderId=%s", $this->existingCerts[$commonName]['id']));
        return $cert;
    }

    function getCertificateZip($commonName) {
        $this->log(sprintf("Getting ZIP certificate for CN %s.", $commonName));
        if(empty($this->existingCerts))
            $this->getCertificates();
        if(!array_key_exists($commonName, $this->existingCerts)) {
            $this->log("No signed certificate found with this CN.");
            return false;
        }
        $cert = $this->request(sprintf("/CertList/DownLoadCert?orderId=%s", $this->existingCerts[$commonName]['id']));
        return $cert;

    }

    function verifyDomains($domains) {
        $this->log("Verifying domains.");
        $check = $this->post("/Certificates/Checkdomains", array("domains" => implode("\n", $domains)));
        if(!$check)
            return false;
        $check = json_decode($check);
        return $check->status === 1 ? true:false;
    }

    function verifyCsr() {
        $this->log("Verifying CSR.");
        $check = $this->post("/UserRequstFile/CheckCSR", array("csr" => $this->getCsr()));
        return $check[0] === "1" ? true:false;
    }

    function newPrivateKey() {
        $this->log("Creating new PK.");
        $pk = openssl_pkey_new($this->opensslSettings);
        if($pk !== FALSE)
            $this->privateKey = $pk;
        return true;
    }

    function getPrivateKey() {
        $this->log("Getting PK.");
        if(is_null($this->privateKey))
            $this->newPrivateKey();
        openssl_pkey_export($this->privateKey, $privateKey);
        return $privateKey;
    }

    function newCsr() {
        $this->log("Creating new CSR.");
        if(is_null($this->privateKey))
            $this->newPrivateKey();
        $this->csr = openssl_csr_new($this->defaultDn, $this->privateKey, $this->opensslSettings);
        return true;
    }

    function getCsr() {
        $this->log("Getting CSR.");
        if(is_null($this->csr))
            $this->newCsr();
        openssl_csr_export($this->csr, $csr);
        return $csr;
    }

    function newCertificate($domains) {
        $this->log("Requesting new certificate.");
        if(is_null($this->privateKey))
            $this->newPrivateKey();
        if(is_null($this->csr))
            $this->newCsr();
        if(empty($domains) || !is_array($domains))
            return false;
        if(!$this->verifyDomains($domains))
            return false;
        if(!$this->verifyCsr())
            return false;
        $request = $this->post("/Certificates/ssl", array("domains" => implode("\n", $domains), "areaCSR" => $this->getCsr(), "rbcsr" => "scsr", "CsrkeySize" => "1"));
        if($request !== false)
            return true;
        return false;
    }

    function log($line, $exit = false) {
        if($this->logging) error_log($line);
        if($exit)
            exit(1);
    }
}