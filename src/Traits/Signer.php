<?php

namespace DazzaDev\SriSigner\Traits;

use DOMDocument;
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

        // 3️⃣ Crear objeto de firma
        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        // Agregar referencia al nodo raíz
        $objDSig->addReference(
            $root,
            XMLSecurityDSig::SHA1,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
            ['uri' => '#comprobante']
        );

        // 4️⃣ Crear clave de firma (SHA1 + RSA)
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'private']);
        $objKey->loadKey($privateKey, false);

        // 5️⃣ Firmar el documento
        $objDSig->sign($objKey);

        // 6️⃣ Agregar información del certificado público
        $objDSig->add509Cert($publicCert, true, false, ['issuerSerial' => true]);

        // 7️⃣ Insertar la firma dentro del XML
        $objDSig->appendSignature($root);

        return $xml->saveXML($xml);
    }
}
