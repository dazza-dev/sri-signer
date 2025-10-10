<?php

namespace DazzaDev\SriSigner\Traits;

use DOMDocument;
use DOMElement;
use DateTime;
use DateTimeZone;
use Exception;

trait Signer
{
    private array $randomNumbers = [];

    /**
     * Sign the XML document with XAdES-BES format
     */
    public function sign(DOMDocument $xml): string
    {
        // Generate the 8 random numbers required for XAdES structure
        $this->generateRandomNumbers();

        // Create signature structure and add it to the document temporarily
        $signatureElement = $this->createSignatureStructure($xml);
        $xml->documentElement->appendChild($signatureElement);

        // Get the formatted XML with proper indentation
        $xml->formatOutput = true;
        $xmlString = $xml->saveXML();

        // Remove the signature element from the original document
        $xml->documentElement->removeChild($signatureElement);

        return $xmlString;
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

        $digestMethod1 = $xml->createElement('ds:DigestMethod');
        $digestMethod1->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $reference1->appendChild($digestMethod1);

        $digestValue1 = $xml->createElement('ds:DigestValue');
        $reference1->appendChild($digestValue1);

        // Add Reference1 to SignedInfo
        $signedInfo->appendChild($reference1);

        // Reference to KeyInfo
        $reference2 = $xml->createElement('ds:Reference');
        $reference2->setAttribute('URI', '#Certificate' . $this->randomNumbers['certificate']);

        $digestMethod2 = $xml->createElement('ds:DigestMethod');
        $digestMethod2->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $reference2->appendChild($digestMethod2);

        $digestValue2 = $xml->createElement('ds:DigestValue');
        $reference2->appendChild($digestValue2);

        // Add Reference2 to SignedInfo
        $signedInfo->appendChild($reference2);

        // Reference to comprobante (root element)
        $reference3 = $xml->createElement('ds:Reference');
        $reference3->setAttribute('Id', 'Reference-ID-' . $this->randomNumbers['referenceId']);
        $reference3->setAttribute('URI', '#comprobante');

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

        // Add Reference3 to SignedInfo
        $signedInfo->appendChild($reference3);

        return $signedInfo;
    }

    /**
     * Create the KeyInfo element
     */
    private function createKeyInfo(DOMDocument $xml): DOMElement
    {
        $keyInfo = $xml->createElement('ds:KeyInfo');
        $keyInfo->setAttribute('Id', 'Certificate' . $this->randomNumbers['certificate']);

        // X509Data
        $x509Data = $xml->createElement('ds:X509Data');
        $x509Certificate = $xml->createElement('ds:X509Certificate');

        // Get clean certificate data without metadata
        $x509Certificate->nodeValue = $this->getCleanX509Certificate();
        $x509Data->appendChild($x509Certificate);
        $keyInfo->appendChild($x509Data);

        // KeyValue
        $keyValue = $xml->createElement('ds:KeyValue');
        $rsaKeyValue = $xml->createElement('ds:RSAKeyValue');

        // Extract public key details
        $publicKey = openssl_pkey_get_public($this->getPublicCert());
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
    private function createObject(DOMDocument $xml): DOMElement
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
        $digestValue->nodeValue = base64_encode(sha1(base64_decode($this->getCleanX509Certificate()), true));
        $certDigest->appendChild($digestValue);
        $cert->appendChild($certDigest);

        $issuerSerial = $xml->createElement('etsi:IssuerSerial');
        $x509IssuerName = $xml->createElement('ds:X509IssuerName');

        // Extract issuer name from certificate instead of using hardcoded value
        $certDetails = $this->getCertificateDetails();
        $issuerName = $this->formatIssuerName($certDetails['issuer']);
        $x509IssuerName->nodeValue = $issuerName;
        $issuerSerial->appendChild($x509IssuerName);

        $x509SerialNumber = $xml->createElement('ds:X509SerialNumber');
        // Convert serial number from hex to decimal format
        $serialHex = $certDetails['serialNumber'];
        $serialDecimal = $this->hexToDecimal($serialHex);
        $x509SerialNumber->nodeValue = $serialDecimal;
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
        $references = $signedInfo->getElementsByTagName('ds:Reference');

        foreach ($references as $reference) {
            $uri = $reference->getAttribute('URI');
            $digestValue = $reference->getElementsByTagName('ds:DigestValue')->item(0);

            if (strpos($uri, '#Signature') === 0 && strpos($uri, 'SignedProperties') !== false) {
                // Hash of SignedProperties
                $signedProperties = $object->getElementsByTagName('etsi:SignedProperties')->item(0);
                $canonicalized = $this->canonicalizeElement($signedProperties);
                $hash = base64_encode(sha1($canonicalized, true));
                $digestValue->nodeValue = $hash;
            } elseif (strpos($uri, '#Certificate') === 0) {
                // Hash of KeyInfo
                $canonicalized = $this->canonicalizeElement($keyInfo);
                $hash = base64_encode(sha1($canonicalized, true));
                $digestValue->nodeValue = $hash;
            } elseif ($uri === '#comprobante') {
                // Hash of comprobante (root element without signature)
                $rootClone = $xml->documentElement->cloneNode(true);
                // Remove any existing signature elements
                $signatures = $rootClone->getElementsByTagName('ds:Signature');
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
    private function canonicalizeElement(DOMElement $element)
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
        $privateKey = openssl_pkey_get_private($this->getPrivateKey());
        if (!$privateKey) {
            throw new Exception("Failed to load private key");
        }

        $signature = '';
        if (!openssl_sign($canonicalized, $signature, $privateKey, OPENSSL_ALGO_SHA1)) {
            throw new Exception("Failed to create digital signature");
        }

        $signatureValue->nodeValue = base64_encode($signature);

        return $signatureValue;
    }

    /**
     * Convert hexadecimal serial number to decimal format
     */
    public function hexToDecimal(string $hex): string
    {
        // Remove any spaces or colons from hex string
        $hex = str_replace([':', ' '], '', $hex);

        // Convert hex to decimal using bcmath for large numbers
        if (function_exists('bcadd')) {
            $decimal = '0';
            $base = '1';

            for ($i = strlen($hex) - 1; $i >= 0; $i--) {
                $digit = hexdec($hex[$i]);
                $decimal = bcadd($decimal, bcmul($digit, $base));
                $base = bcmul($base, '16');
            }

            return $decimal;
        }

        // Fallback for systems without bcmath
        return (string) hexdec($hex);
    }
}
