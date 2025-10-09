<?php

namespace DazzaDev\SriSigner\Actions;

use DOMDocument;
use DazzaDev\SriXmlGenerator\XmlHelper;
use DazzaDev\SriXmlGenerator\Models\Invoice\Invoice;
use DazzaDev\SriSigner\Exceptions\DocumentException;
use Lopezsoft\UBL21dian\Templates\SOAP\SendBillSync;
use Lopezsoft\UBL21dian\Templates\SOAP\SendTestSetAsync;

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
     * Document
     */
    private Invoice $document;

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
        $signDocument = $this->signDocument();

        return $signDocument;
    }

    /**
     * Sign document
     */
    public function signDocument()
    {
        $signDocument = $this->sign($this->documentXml);
        $this->signedDocument = $signDocument;

        return $signDocument;
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
        $this->document = (new Invoice($this->documentData));
        $this->documentXml = (new XmlHelper)->getXml(
            $this->documentType,
            $this->document->toArray()
        );
    }
}
