<?php

namespace DazzaDev\SriSigner\Actions;

use DOMDocument;
use DazzaDev\SriXmlGenerator\XmlHelper;
use DazzaDev\SriXmlGenerator\Models\Invoice\Invoice;
use DazzaDev\SriSigner\Exceptions\DocumentException;
use DazzaDev\SriSigner\AccessKeyGenerator;

trait Document
{
    /**
     * Document type
     */
    private string $documentType;

    /**
     * Document data
     */
    private array $documentData;

    /**
     * Document XML
     */
    private DOMDocument $documentXml;

    /**
     * Signed document
     */
    private string $signedDocument;

    /**
     * Send document
     */
    public function sendDocument()
    {
        // Sign document
        $this->signDocument();

        // Send document
        $validate = $this->validate($this->signedDocument);

        if (!$validate['success']) {
            throw new DocumentException($validate['status'] . ' - ' . $validate['error']);
        }

        sleep(3);

        $authorize = $this->authorize($this->getAccessKey());
        //$authorize = $this->authorize('0310202501019512705000110010010000000081680242518');

        if (!$authorize['success']) {
            throw new DocumentException($authorize['status'] . ' - ' . $authorize['error']);
        }

        print_r($authorize);

        return $this->signedDocument;
    }

    /**
     * Sign document
     */
    public function signDocument()
    {
        $this->signedDocument = $this->sign($this->documentXml);

        return $this->signedDocument;
    }

    /**
     * Set document type
     */
    public function setDocumentType(string $documentType): void
    {
        $this->documentType = $documentType;
    }

    /**
     * Set document data
     */
    public function setDocumentData(array $documentData): void
    {
        $this->documentData = $documentData;

        // Set access key
        $this->accessKey = AccessKeyGenerator::generate(
            $this->documentType,
            $documentData
        );

        // Create document instance
        $this->document = new Invoice(
            $this->accessKey,
            $this->documentData
        );

        // Generate document XML
        $this->documentXml = (new XmlHelper)->getXml(
            $this->documentType,
            $this->document->toArray()
        );
    }
}
