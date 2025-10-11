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

    private string $hashComprobante = '';

    private string $hashSignedProperties = '';

    private string $hashKeyInfo = '';

    /**
     * Sign the XML document with XAdES-BES format
     */
    public function sign(DOMDocument $xml): string
    {
        // Generate the 8 random numbers required for XAdES structure
        $this->generateRandomNumbers();

        // Get hash of comprobante element
        $this->hashComprobante = $this->getHashComprobante($xml);

        // Create signature structure and add it to the document temporarily
        $signatureElement = $this->createSignatureStructure($xml);
        $xml->documentElement->appendChild($signatureElement);

        // Get the formatted XML with proper indentation but remove signature indentation
        $xml->formatOutput = true;
        $xmlString = $xml->saveXML();

        // Remove indentation from signature elements only
        $xmlString = $this->removeSignatureIndentation($xmlString);

        // Remove the signature element from the original document
        $xml->documentElement->removeChild($signatureElement);

        return $xmlString;
    }

    /**
     * Remove indentation from signature elements while preserving original XML formatting
     */
    private function removeSignatureIndentation(string $xmlString): string
    {
        // Pattern to match signature elements with indentation
        $pattern = '/(\s+)(<ds:Signature[^>]*>.*?<\/ds:Signature>)/s';

        return preg_replace_callback($pattern, function ($matches) {
            $indentation = $matches[1];
            $signatureContent = $matches[2];

            // Remove all indentation from signature content
            $signatureContent = preg_replace('/\n\s+/', '', $signatureContent);

            // Return signature without indentation but preserve the original line break
            return "\n" . $signatureContent;
        }, $xmlString);
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

        // Create Object with XAdES properties
        $object = $this->createObject($xml);
        $signature->appendChild($object);

        // Create KeyInfo
        $keyInfo = $this->createKeyInfo($xml);
        $signature->appendChild($keyInfo);

        // Create SignedInfo
        $signedInfo = $this->createSignedInfo($xml);
        $signature->appendChild($signedInfo);

        // Create SignatureValue
        $signatureValue = $this->createSignatureValue($xml, $signedInfo);
        $signature->insertBefore($signatureValue, $keyInfo);

        // Calculate hashes for references
        $this->calculateReferenceHashes($xml, $signedInfo, $keyInfo, $object);

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
        $digestValue1->nodeValue = $this->hashSignedProperties;
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
        $digestValue2->nodeValue = $this->hashKeyInfo;
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
        $digestValue3->nodeValue = $this->hashComprobante;
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

        // Get formatted certificate data with line breaks every 76 characters
        $x509Certificate->nodeValue = $this->getFormattedX509Certificate();
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

        // Calculate hash of KeyInfo
        $canonicalizedKeyInfo = $this->canonicalizeElement($keyInfo);
        $this->hashKeyInfo = $this->sha1Base64($canonicalizedKeyInfo);

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

        // Add DigestValue for certificate digest
        $digestValue = $xml->createElement('ds:DigestValue');

        // Calculate SHA1 hash of certificate in DER format
        $digestValue->nodeValue = $this->sha1Base64($this->getDerBinary());
        $certDigest->appendChild($digestValue);
        $cert->appendChild($certDigest);

        $issuerSerial = $xml->createElement('etsi:IssuerSerial');

        // Add X509IssuerName for certificate issuer name
        $x509IssuerName = $xml->createElement('ds:X509IssuerName');
        $x509IssuerName->nodeValue = $this->getIssuerName();
        $issuerSerial->appendChild($x509IssuerName);

        // Add X509SerialNumber for certificate serial number
        $x509SerialNumber = $xml->createElement('ds:X509SerialNumber');
        $x509SerialNumber->nodeValue = $this->getCertificateSerialNumber();
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

        // Canonicalize SignedProperties and generate its hash
        $canonicalizedSignedProperties = $this->canonicalizeElement($signedProperties);
        $this->hashSignedProperties = $this->sha1Base64($canonicalizedSignedProperties);

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
                $digestValue->nodeValue = $this->hashSignedProperties;
            } elseif (strpos($uri, '#Certificate') === 0) {
                $digestValue->nodeValue = $this->hashKeyInfo;
            } elseif ($uri === '#comprobante') {
                $digestValue->nodeValue = $this->hashComprobante;
            }
        }
    }

    /**
     * Get hash of comprobante element
     */
    private function getHashComprobante(DOMDocument $xml): string
    {
        // Hash of comprobante (root element without signature)
        $rootClone = $xml->documentElement->cloneNode(true);

        // Create a new document and import the cloned element
        $tempDoc = new DOMDocument('1.0', 'UTF-8');
        $importedRoot = $tempDoc->importNode($rootClone, true);
        $tempDoc->appendChild($importedRoot);

        // Remove any existing signature elements from the imported element
        $signatures = $importedRoot->getElementsByTagName('Signature');
        $removedCount = 0;
        while ($signatures->length > 0) {
            $signatures->item(0)->parentNode->removeChild($signatures->item(0));
            $removedCount++;
        }

        // Also check for ds:Signature elements
        $dsSignatures = $importedRoot->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
        while ($dsSignatures->length > 0) {
            $dsSignatures->item(0)->parentNode->removeChild($dsSignatures->item(0));
            $removedCount++;
        }

        $canonicalized = $importedRoot->C14N();
        $hash = $this->sha1Base64($canonicalized);

        return $hash;
    }

    /**
     * Canonicalize an element with proper namespaces
     */
    private function canonicalizeElement(DOMElement $element)
    {
        // Create a new document to ensure proper namespace context
        $tempDoc = new DOMDocument('1.0', 'UTF-8');

        // Import the element into the new document with deep copy
        $importedElement = $tempDoc->importNode($element, true);
        $tempDoc->appendChild($importedElement);

        // Ensure namespaces are properly declared on the root element
        $importedElement->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');
        $importedElement->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:etsi', 'http://uri.etsi.org/01903/v1.3.2#');

        // Use C14N on the imported element
        return $importedElement->C14N();
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
     * Calculate SHA1 hash and encode to base64
     */
    private function sha1Base64(string $text): string
    {
        return base64_encode(sha1($text, true));
    }
}
