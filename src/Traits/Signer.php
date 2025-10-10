<?php

namespace DazzaDev\SriSigner\Traits;

use DOMDocument;
use DOMElement;
use DateTime;
use DateTimeZone;

trait Signer
{
    private array $randomNumbers = [];

    /**
     * Sign the XML document with XAdES-BES format
     */
    public function sign(DOMDocument $xml): DOMDocument
    {
        // Generate the 8 random numbers required for XAdES structure
        $this->generateRandomNumbers();

        // Create signature structure
        $signatureElement = $this->createSignatureStructure($xml);

        // Append signature to the root element
        $xml->documentElement->appendChild($signatureElement);

        return $xml;
    }

    /**
     * Generate the 8 random numbers required for XAdES structure
     */
    private function generateRandomNumbers(): void
    {
        $this->randomNumbers = [
            'certificate' => rand(1, 100000),
            'signature' => rand(1, 100000),
            'signedProperties' => rand(1, 100000),
            'signedInfo' => rand(1, 100000),
            'signedPropertiesId' => rand(1, 100000),
            'referenceId' => rand(1, 100000),
            'signatureValue' => rand(1, 100000),
            'object' => rand(1, 100000)
        ];
    }

    /**
     * Load and parse the P12 certificate
     */
    private function loadCertificate(): array
    {
        if (!file_exists($this->certificatePath)) {
            throw new \Exception("Certificate file not found: {$this->certificatePath}");
        }

        $p12Content = file_get_contents($this->certificatePath);
        $certificates = [];

        if (!openssl_pkcs12_read($p12Content, $certificates, $this->certificatePassword)) {
            throw new \Exception("Failed to read P12 certificate");
        }

        return $certificates;
    }

    /**
     * Create the complete signature structure
     */
    private function createSignatureStructure(DOMDocument $xml): DOMElement
    {
        $signature = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Signature');
        $signature->setAttribute('Id', 'Signature' . $this->randomNumbers['signature']);
        $signature->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');
        $signature->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:etsi', 'http://uri.etsi.org/01903/v1.3.2#');

        // Create SignedInfo
        $signedInfo = $this->createSignedInfo($xml);
        $signature->appendChild($signedInfo);

        // Create KeyInfo
        $keyInfo = $this->createKeyInfo($xml);
        $signature->appendChild($keyInfo);

        // Create Object with XAdES properties
        $object = $this->createObject($xml);
        $signature->appendChild($object);

        // Calculate hashes for references
        $this->calculateReferenceHashes($xml, $signedInfo, $keyInfo, $object);

        // Create SignatureValue
        $signatureValue = $this->createSignatureValue($xml, $signedInfo);
        $signature->insertBefore($signatureValue, $keyInfo);

        return $signature;
    }

    /**
     * Create the SignedInfo element
     */
    private function createSignedInfo(DOMDocument $xml): DOMElement
    {
        $signedInfo = $xml->createElement('ds:SignedInfo');
        $signedInfo->setAttribute('Id', 'Signature-SignedInfo' . $this->randomNumbers['signedInfo']);

        // CanonicalizationMethod
        $canonicalizationMethod = $xml->createElement('ds:CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        $signedInfo->appendChild($canonicalizationMethod);

        // SignatureMethod
        $signatureMethod = $xml->createElement('ds:SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
        $signedInfo->appendChild($signatureMethod);

        // Reference to SignedProperties
        $reference1 = $xml->createElement('ds:Reference');
        $reference1->setAttribute('Id', 'SignedPropertiesID' . $this->randomNumbers['signedPropertiesId']);
        $reference1->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
        $reference1->setAttribute('URI', '#Signature' . $this->randomNumbers['signature'] . '-SignedProperties' . $this->randomNumbers['signedProperties']);

        $transforms1 = $xml->createElement('ds:Transforms');
        $transform1 = $xml->createElement('ds:Transform');
        $transform1->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        $transforms1->appendChild($transform1);
        $reference1->appendChild($transforms1);

        $digestMethod1 = $xml->createElement('ds:DigestMethod');
        $digestMethod1->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $reference1->appendChild($digestMethod1);

        $digestValue1 = $xml->createElement('ds:DigestValue');
        $reference1->appendChild($digestValue1);

        $signedInfo->appendChild($reference1);

        // Reference to KeyInfo
        $reference2 = $xml->createElement('ds:Reference');
        $reference2->setAttribute('URI', '#Certificate' . $this->randomNumbers['certificate']);

        $transforms2 = $xml->createElement('ds:Transforms');
        $transform2 = $xml->createElement('ds:Transform');
        $transform2->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        $transforms2->appendChild($transform2);
        $reference2->appendChild($transforms2);

        $digestMethod2 = $xml->createElement('ds:DigestMethod');
        $digestMethod2->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $reference2->appendChild($digestMethod2);

        $digestValue2 = $xml->createElement('ds:DigestValue');
        $reference2->appendChild($digestValue2);

        $signedInfo->appendChild($reference2);

        // Reference to comprobante (root element)
        $reference3 = $xml->createElement('ds:Reference');
        $reference3->setAttribute('Id', 'Reference-ID-' . $this->randomNumbers['referenceId']);
        $reference3->setAttribute('URI', '');

        $transforms3 = $xml->createElement('ds:Transforms');
        $transform3 = $xml->createElement('ds:Transform');
        $transform3->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        $transforms3->appendChild($transform3);
        $reference3->appendChild($transforms3);

        $digestMethod3 = $xml->createElement('ds:DigestMethod');
        $digestMethod3->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $reference3->appendChild($digestMethod3);

        $digestValue3 = $xml->createElement('ds:DigestValue');
        $reference3->appendChild($digestValue3);

        $signedInfo->appendChild($reference3);

        return $signedInfo;
    }

    /**
     * Create the KeyInfo element
     */
    private function createKeyInfo(DOMDocument $xml, array $certificate): DOMElement
    {
        $keyInfo = $xml->createElement('ds:KeyInfo');
        $keyInfo->setAttribute('Id', 'Certificate' . $this->randomNumbers['certificate']);

        // X509Data
        $x509Data = $xml->createElement('ds:X509Data');
        $x509Certificate = $xml->createElement('ds:X509Certificate');

        // Extract certificate in PEM format without headers and format to 76 chars per line
        $certData = $certificate['cert'];
        $certPem = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r"], '', $certData);
        $certFormatted = chunk_split($certPem, 76, "\n");
        $certFormatted = trim($certFormatted);

        $x509Certificate->nodeValue = $certFormatted;
        $x509Data->appendChild($x509Certificate);
        $keyInfo->appendChild($x509Data);

        // KeyValue
        $keyValue = $xml->createElement('ds:KeyValue');
        $rsaKeyValue = $xml->createElement('ds:RSAKeyValue');

        // Extract public key details
        $publicKey = openssl_pkey_get_public($certificate['cert']);
        $keyDetails = openssl_pkey_get_details($publicKey);

        $modulus = $xml->createElement('ds:Modulus');
        $modulus->nodeValue = base64_encode($keyDetails['rsa']['n']);
        $rsaKeyValue->appendChild($modulus);

        $exponent = $xml->createElement('ds:Exponent');
        $exponent->nodeValue = base64_encode($keyDetails['rsa']['e']);
        $rsaKeyValue->appendChild($exponent);

        $keyValue->appendChild($rsaKeyValue);
        $keyInfo->appendChild($keyValue);

        return $keyInfo;
    }

    /**
     * Create the Object element with XAdES properties
     */
    private function createObject(DOMDocument $xml, array $certificate): DOMElement
    {
        $object = $xml->createElement('ds:Object');
        $object->setAttribute('Id', 'Signature' . $this->randomNumbers['signature'] . '-Object' . $this->randomNumbers['object']);

        $qualifyingProperties = $xml->createElement('etsi:QualifyingProperties');
        $qualifyingProperties->setAttribute('Target', '#Signature' . $this->randomNumbers['signature']);

        $signedProperties = $xml->createElement('etsi:SignedProperties');
        $signedProperties->setAttribute('Id', 'Signature' . $this->randomNumbers['signature'] . '-SignedProperties' . $this->randomNumbers['signedProperties']);

        // SignedSignatureProperties
        $signedSignatureProperties = $xml->createElement('etsi:SignedSignatureProperties');

        // SigningTime
        $signingTime = $xml->createElement('etsi:SigningTime');
        $now = new DateTime('now', new DateTimeZone('America/Guayaquil'));
        $signingTime->nodeValue = $now->format('Y-m-d\TH:i:sP');
        $signedSignatureProperties->appendChild($signingTime);

        // SigningCertificate
        $signingCertificate = $xml->createElement('etsi:SigningCertificate');
        $cert = $xml->createElement('etsi:Cert');

        $certDigest = $xml->createElement('etsi:CertDigest');
        $digestMethod = $xml->createElement('ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $certDigest->appendChild($digestMethod);

        $digestValue = $xml->createElement('ds:DigestValue');
        // Calculate SHA1 hash of certificate in DER format
        $certDer = openssl_x509_read($certificate['cert']);
        openssl_x509_export($certDer, $certPem);
        $certDerBinary = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r"], '', $certPem));
        $digestValue->nodeValue = base64_encode(sha1($certDerBinary, true));
        $certDigest->appendChild($digestValue);
        $cert->appendChild($certDigest);

        $issuerSerial = $xml->createElement('etsi:IssuerSerial');
        $x509IssuerName = $xml->createElement('ds:X509IssuerName');
        $x509IssuerName->nodeValue = 'CN=AC BANCO CENTRAL DEL ECUADOR,L=QUITO,OU=ENTIDAD DE CERTIFICACION DE INFORMACION-ECIBCE,O=BANCO CENTRAL DEL ECUADOR,C=EC';
        $issuerSerial->appendChild($x509IssuerName);

        $x509SerialNumber = $xml->createElement('ds:X509SerialNumber');
        $certDetails = openssl_x509_parse($certificate['cert']);
        $x509SerialNumber->nodeValue = $certDetails['serialNumber'];
        $issuerSerial->appendChild($x509SerialNumber);

        $cert->appendChild($issuerSerial);
        $signingCertificate->appendChild($cert);
        $signedSignatureProperties->appendChild($signingCertificate);

        $signedProperties->appendChild($signedSignatureProperties);

        // SignedDataObjectProperties
        $signedDataObjectProperties = $xml->createElement('etsi:SignedDataObjectProperties');
        $dataObjectFormat = $xml->createElement('etsi:DataObjectFormat');
        $dataObjectFormat->setAttribute('ObjectReference', '#Reference-ID-' . $this->randomNumbers['referenceId']);

        $description = $xml->createElement('etsi:Description');
        $description->nodeValue = 'contenido comprobante';
        $dataObjectFormat->appendChild($description);

        $mimeType = $xml->createElement('etsi:MimeType');
        $mimeType->nodeValue = 'text/xml';
        $dataObjectFormat->appendChild($mimeType);

        $signedDataObjectProperties->appendChild($dataObjectFormat);
        $signedProperties->appendChild($signedDataObjectProperties);

        $qualifyingProperties->appendChild($signedProperties);
        $object->appendChild($qualifyingProperties);

        return $object;
    }

    /**
     * Calculate hashes for all references in SignedInfo
     */
    private function calculateReferenceHashes(DOMDocument $xml, DOMElement $signedInfo, DOMElement $keyInfo, DOMElement $object): void
    {
        $references = $signedInfo->getElementsByTagName('Reference');

        foreach ($references as $reference) {
            $uri = $reference->getAttribute('URI');
            $digestValue = $reference->getElementsByTagName('DigestValue')->item(0);

            if (strpos($uri, '#Signature') === 0 && strpos($uri, 'SignedProperties') !== false) {
                // Hash of SignedProperties
                $signedProperties = $object->getElementsByTagName('SignedProperties')->item(0);
                $canonicalized = $this->canonicalizeElement($signedProperties);
                $hash = base64_encode(sha1($canonicalized, true));
                $digestValue->nodeValue = $hash;
            } elseif (strpos($uri, '#Certificate') === 0) {
                // Hash of KeyInfo
                $canonicalized = $this->canonicalizeElement($keyInfo);
                $hash = base64_encode(sha1($canonicalized, true));
                $digestValue->nodeValue = $hash;
            } elseif ($uri === '') {
                // Hash of comprobante (root element without signature)
                $rootClone = $xml->documentElement->cloneNode(true);
                // Remove any existing signature elements
                $signatures = $rootClone->getElementsByTagName('Signature');
                while ($signatures->length > 0) {
                    $signatures->item(0)->parentNode->removeChild($signatures->item(0));
                }
                $hash = base64_encode(sha1($rootClone->C14N(), true));
                $digestValue->nodeValue = $hash;
            }
        }
    }

    /**
     * Canonicalize an element with proper namespaces
     */
    private function canonicalizeElement(DOMElement $element): string
    {
        // Add required namespaces for canonicalization
        $element->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');
        $element->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:etsi', 'http://uri.etsi.org/01903/v1.3.2#');

        return $element->C14N();
    }

    /**
     * Create the SignatureValue element
     */
    private function createSignatureValue(DOMDocument $xml, DOMElement $signedInfo): DOMElement
    {
        $signatureValue = $xml->createElement('ds:SignatureValue');
        $signatureValue->setAttribute('Id', 'SignatureValue' . $this->randomNumbers['signatureValue']);

        // Canonicalize SignedInfo
        $canonicalized = $this->canonicalizeElement($signedInfo);

        // Sign with private key
        $privateKey = openssl_pkey_get_private($certificate['pkey']);
        if (!$privateKey) {
            throw new \Exception("Failed to load private key");
        }

        $signature = '';
        if (!openssl_sign($canonicalized, $signature, $privateKey, OPENSSL_ALGO_SHA1)) {
            throw new \Exception("Failed to create digital signature");
        }

        $signatureValue->nodeValue = base64_encode($signature);

        return $signatureValue;
    }
}
