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

        // CORRECCIÓN 1: Usar C14N (Canonicalización No Exclusiva)
        $objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);

        // --- 2. Crear IDs y Nombres Requeridos para XAdES ---
        // En XAdES, todos los nodos principales (Signature, KeyInfo, SignedProperties) deben tener un ID.
        $signatureId = 'Signature-1312421384'; // Use un ID dinámico y único aquí (ej: basado en tiempo o hash)
        $keyInfoId = 'KeyInfoId-' . $signatureId;
        $signedPropsId = 'SignedProperties-' . $signatureId;

        // Establecer el ID de la firma
        $objDSig->sigNode->setAttribute('Id', $signatureId);

        // --- 3. Generar el Bloque XAdES (ds:Object y etsi:QualifyingProperties) ---
        // El bloque XAdES contiene las propiedades firmadas (hora, política, etc.).
        $qualifyingProperties = $this->generateSignedProperties($xml, $signedPropsId, $signatureId);

        $objNode = $xml->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:Object');
        $objNode->appendChild($qualifyingProperties);
        $root->appendChild($objNode);

        // --- 4. Agregar las 3 Referencias Requeridas por XAdES ---

        // a) Referencia al 'ds:KeyInfo' (siempre necesaria en XAdES para asegurar el certificado)
        $keyInfo = $xml->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:KeyInfo');
        $keyInfo->setAttribute('Id', $keyInfoId);

        // a) Referencia a KeyInfo (sin el nodo KeyInfo AÚN, la librería lo generará con add509Cert)
        $objDSig->addReference(
            $xml->documentElement,
            XMLSecurityDSig::SHA1,
            ['http://www.w3.org/2001/10/xml-exc-c14n#'], // <-- Añadir C14N Exclusiva
            ['uri' => '#' . $keyInfoId]
        );

        // b) Referencia a Factura
        $objDSig->addReference(
            $root,
            XMLSecurityDSig::SHA1,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
            ['uri' => '#comprobante', 'id' => 'Reference-' . $signatureId]
        );

        // c) Referencia al 'etsi:SignedProperties'
        $objDSig->addReference(
            $qualifyingProperties,
            XMLSecurityDSig::SHA1,
            [],
            ['uri' => '#' . $signedPropsId, 'type' => 'http://uri.etsi.org/01903#SignedProperties']
        );

        // --- 5. Firmar y Finalizar ---

        // La clave para firmar (SHA1 + RSA)
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'private']);
        $objKey->loadKey($this->getPrivateKey(), false);

        // Firmar el documento. Los DigestValues se calculan en este paso.
        $objDSig->sign($objKey);

        // Añadir la información del certificado (X509Data)
        // Nota: El certificado debe incluir la Serial del emisor, como en el XML válido.
        $objDSig->add509Cert($this->getPublicCert(), true, false, ['issuerSerial' => true]);

        // El 'ds:Signature' debe estar en el XML *antes* de calcular las referencias.
        // Usamos esta referencia temporal para generar el SignedInfo y luego calcular los DigestValues
        $objDSig->appendSignature($root);

        // Cleanup: Eliminar el 'Id' del nodo raíz si fue agregado temporalmente.
        if ($root->hasAttribute('Id')) {
            $root->removeAttribute('Id');
        }

        return $xml->saveXML($xml);
    }


    protected function generateSignedProperties(DOMDocument $xml, string $signedPropsId, string $signatureId): DOMElement
    {
        // Obtenga la información del certificado para el IssuerSerial
        $cert = $this->getPublicCert();
        $certData = openssl_x509_parse($cert);

        // Extraer el IssuerName y SerialNumber para el X509IssuerSerial
        // Esta lógica puede variar dependiendo de cómo esté cargando su certificado
        $issuerName = 'CN=AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, O=SECURITY DATA S.A. 2, C=EC'; // Reemplazar con valor real
        $issuerSerial = '238886640'; // Reemplazar con valor real del certificado
        $certDigestValue = 'eGO//OyySge9HZ027CZUoHvG/jI='; // Reemplazar con el SHA1 del certificado

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
        $dataObjectFormat->setAttribute('ObjectReference', 'Reference-' . $signatureId); // Usar el ID de la referencia a la factura

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
