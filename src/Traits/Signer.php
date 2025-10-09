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

        // Sign Object
        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        // Add reference to root node
        $objDSig->addReference(
            $root,
            XMLSecurityDSig::SHA1,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
            ['uri' => '#comprobante']
        );

        // Add key for signing (SHA1 + RSA)
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'private']);
        $objKey->loadKey($this->getPrivateKey(), false);

        // Sign document
        $objDSig->sign($objKey);

        // Add public certificate information
        $objDSig->add509Cert($this->getPublicCert(), true, false, ['issuerSerial' => true]);

        // Insert signature into XML
        $objDSig->appendSignature($root);

        // Remove Id attribute if present
        if ($root->hasAttribute('Id')) {
            $root->removeAttribute('Id');
        }

        return $xml->saveXML($xml);
    }
}
