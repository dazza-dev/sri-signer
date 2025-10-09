<?php

namespace DazzaDev\SriSigner\Traits;

use DOMDocument;
use DOMElement;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

trait Signer
{
    public function sign(DOMDocument $xml): string
    {
        $root = $xml->documentElement;
        if (!$root->hasAttribute('id')) {
            $root->setAttribute('id', 'comprobante');
        }

        // --- 1. Inicialización de la Firma y Canonicalización ---
        $objDSig = new XMLSecurityDSig();

        // CORRECCIÓN: Usar C14N (Canonicalización No Exclusiva) como en archivo válido SRI
        $objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);

        // --- 2. Crear IDs y Nombres Requeridos para XAdES ---
        // Generate unique ID based on timestamp and random component
        $uniqueId = uniqid('', true);
        $signatureId = 'Signature-' . $uniqueId;
        $keyInfoId = 'KeyInfoId-' . $signatureId;
        $signedPropsId = 'SignedProperties-' . $signatureId;
        $signedInfoId = 'Signature-SignedInfo-' . $uniqueId;

        // Establecer el ID de la firma
        $objDSig->sigNode->setAttribute('Id', $signatureId);

        // CORRECCIÓN CRÍTICA: Agregar ID al ds:SignedInfo
        $objDSig->sigNode->getElementsByTagName('SignedInfo')->item(0)->setAttribute('Id', $signedInfoId);

        // --- 3. Generar el Bloque XAdES (ds:Object y etsi:QualifyingProperties) ---
        // El bloque XAdES contiene las propiedades firmadas (hora, política, etc.).
        $qualifyingProperties = $this->generateSignedProperties($xml, $signedPropsId, $signatureId, $uniqueId);

        $objNode = $xml->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:Object');
        // CORRECCIÓN: Evitar namespaces duplicados en el ds:Object
        $objNode->appendChild($qualifyingProperties);

        // --- 4. Agregar Referencias para la Firma ---
        // CORRECCIÓN: Agregar referencia al KeyInfo primero como en archivo válido SRI
        $keyInfoNode = $objDSig->sigNode->getElementsByTagName('KeyInfo')->item(0);
        if (!$keyInfoNode) {
            // Crear un KeyInfo temporal para la referencia
            $keyInfoNode = $xml->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:KeyInfo');
            $keyInfoNode->setAttribute('Id', $keyInfoId);
        }
        
        $objDSig->addReference(
            $keyInfoNode,
            XMLSecurityDSig::SHA1,
            [],
            ['overwrite' => false]
        );

        // Referencia al documento principal (comprobante)
        $objDSig->addReference(
            $root,
            XMLSecurityDSig::SHA1,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
            ['id_name' => 'id', 'overwrite' => false]
        );

        // Referencia a las propiedades firmadas (XAdES)
        $objDSig->addReference(
            $qualifyingProperties->getElementsByTagName('SignedProperties')->item(0),
            XMLSecurityDSig::SHA1,
            [XMLSecurityDSIG::C14N],
            ['overwrite' => false, 'type' => 'http://uri.etsi.org/01903#SignedProperties']
        );

        // Ahora crear la clave y firmar
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'private']);
        $objKey->loadKey($this->getPrivateKey(), false);

        // Firmar el documento
        $objDSig->sign($objKey);

        // Añadir la información del certificado (X509Data) con cadena completa
        $objDSig->add509Cert($this->getPublicCert(), true, false, ['issuerSerial' => true]);
        
        // Agregar certificados intermedios si están disponibles en el certificado
        if (isset($this->certificateData['extracerts']) && is_array($this->certificateData['extracerts'])) {
            foreach ($this->certificateData['extracerts'] as $extraCert) {
                $objDSig->add509Cert($extraCert, false, false);
            }
        }

        // Establecer el ID del KeyInfo después de que se cree
        $keyInfoNode = $objDSig->sigNode->getElementsByTagName('KeyInfo')->item(0);
        if ($keyInfoNode) {
            $keyInfoNode->setAttribute('Id', $keyInfoId);
        }

        // --- CORRECCIÓN: Agregar el ds:Object ANTES de appendSignature ---
        // Importar el nodo ds:Object al documento de la firma antes de agregarlo
        $importedObjNode = $objDSig->sigNode->ownerDocument->importNode($objNode, true);
        $objDSig->sigNode->appendChild($importedObjNode);

        // Adjuntar la firma completa al documento
        $objDSig->appendSignature($root);

        // Cleanup: Eliminar el 'Id' del nodo raíz si fue agregado temporalmente.
        if ($root->hasAttribute('Id')) {
            $root->removeAttribute('Id');
        }

        return $xml->saveXML();
    }


    protected function generateSignedProperties(DOMDocument $xml, string $signedPropsId, string $signatureId, string $uniqueId): DOMElement
    {
        // Obtenga la información del certificado para el IssuerSerial
        $cert = $this->getPublicCert();
        $certData = openssl_x509_parse($cert);

        // Extraer el IssuerName en el formato correcto para SRI Ecuador
        // Formato requerido: CN=..., OU=..., O=..., C=...
        $issuerParts = [];
        if (isset($certData['issuer']['CN'])) {
            $issuerParts[] = 'CN=' . $certData['issuer']['CN'];
        }
        if (isset($certData['issuer']['OU'])) {
            $issuerParts[] = 'OU=' . $certData['issuer']['OU'];
        }
        if (isset($certData['issuer']['O'])) {
            $issuerParts[] = 'O=' . $certData['issuer']['O'];
        }
        if (isset($certData['issuer']['C'])) {
            $issuerParts[] = 'C=' . $certData['issuer']['C'];
        }
        $issuerName = implode(',', $issuerParts);
        $issuerSerial = (string) $certData['serialNumber'];
        
        // Calcular el digest SHA1 del certificado DER (binario)
        $certBinary = base64_decode(preg_replace('/-----[^-]+-----/', '', $cert));
        $certDigestValue = base64_encode(sha1($certBinary, true));

        // Namespaces XAdES
        $etsiNS = 'http://uri.etsi.org/01903/v1.3.2#';
        $dsNS = XMLSecurityDSig::XMLDSIGNS;

        // --- etsi:QualifyingProperties ---
        $qualifyingProperties = $xml->createElementNS($etsiNS, 'etsi:QualifyingProperties');
        $qualifyingProperties->setAttribute('Target', '#' . $signatureId);

        // --- etsi:SignedProperties ---
        $signedProperties = $xml->createElementNS($etsiNS, 'etsi:SignedProperties');
        $signedProperties->setAttribute('Id', $signedPropsId);

        // --- etsi:SignedSignatureProperties ---
        $signedSignatureProperties = $xml->createElementNS($etsiNS, 'etsi:SignedSignatureProperties');

        // etsi:SigningTime
        $signingTime = $xml->createElementNS($etsiNS, 'etsi:SigningTime', gmdate('Y-m-d\TH:i:s.000\Z'));

        // etsi:SigningCertificate
        $signingCertificate = $xml->createElementNS($etsiNS, 'etsi:SigningCertificate');
        $certNode = $xml->createElementNS($etsiNS, 'etsi:Cert');

        // ds:CertDigest (El DigestValue del certificado público)
        $certDigest = $xml->createElementNS($etsiNS, 'etsi:CertDigest');
        $digestMethod = $xml->createElementNS($dsNS, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $digestValue = $xml->createElementNS($dsNS, 'ds:DigestValue', $certDigestValue);
        $certDigest->appendChild($digestMethod);
        $certDigest->appendChild($digestValue);

        // ds:IssuerSerial
        $issuerSerialNode = $xml->createElementNS($etsiNS, 'etsi:IssuerSerial');
        $x509IssuerName = $xml->createElementNS($dsNS, 'ds:X509IssuerName', $issuerName);
        $x509SerialNumber = $xml->createElementNS($dsNS, 'ds:X509SerialNumber', $issuerSerial);
        $issuerSerialNode->appendChild($x509IssuerName);
        $issuerSerialNode->appendChild($x509SerialNumber);

        $certNode->appendChild($certDigest);
        $certNode->appendChild($issuerSerialNode);
        $signingCertificate->appendChild($certNode);

        // etsi:SignaturePolicyIdentifier (Asumimos el Implied, como el XML válido)
        $policyIdentifier = $xml->createElementNS($etsiNS, 'etsi:SignaturePolicyIdentifier');
        $policyImplied = $xml->createElementNS($etsiNS, 'etsi:SignaturePolicyImplied');
        $policyIdentifier->appendChild($policyImplied);

        $signedSignatureProperties->appendChild($signingTime);
        $signedSignatureProperties->appendChild($signingCertificate);
        $signedSignatureProperties->appendChild($policyIdentifier);

        // --- etsi:SignedDataObjectProperties ---
        $signedDataObjectProperties = $xml->createElementNS($etsiNS, 'etsi:SignedDataObjectProperties');
        $dataObjectFormat = $xml->createElementNS($etsiNS, 'etsi:DataObjectFormat');
        $dataObjectFormat->setAttribute('ObjectReference', '#comprobante'); // Referencia correcta al documento

        $description = $xml->createElementNS($etsiNS, 'etsi:Description', 'contenido comprobante');
        $mimeType = $xml->createElementNS($etsiNS, 'etsi:MimeType', 'text/xml');

        $dataObjectFormat->appendChild($description);
        $dataObjectFormat->appendChild($mimeType);
        $signedDataObjectProperties->appendChild($dataObjectFormat);

        $signedProperties->appendChild($signedSignatureProperties);
        $signedProperties->appendChild($signedDataObjectProperties);
        $qualifyingProperties->appendChild($signedProperties);

        return $qualifyingProperties;
    }
}
