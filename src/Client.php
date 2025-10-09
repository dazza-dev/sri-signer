<?php

namespace DazzaDev\SriSigner;

use DazzaDev\SriSigner\Actions\Document;
use DazzaDev\SriSigner\Traits\Certificate;
use DazzaDev\SriSigner\Traits\File;
use DazzaDev\SriSigner\Traits\Listing;
use DazzaDev\SriXmlGenerator\Enums\Environments;
use DazzaDev\SriXmlGenerator\Models\Invoice\Invoice;

use DOMDocument;

class Client
{
    use Certificate;
    use Document;
    use File;
    use Listing;

    /**
     * Is test environment
     */
    private bool $isTestEnvironment;

    /**
     * Environment
     */
    protected array $environment;

    /**
     * Document
     */
    private Invoice $document;

    /**
     * Response SRI
     */
    private $responseSri;

    /**
     * Access key
     */
    private string $accessKey;

    /**
     * Constructor
     */
    public function __construct(bool $test = false)
    {
        $this->isTestEnvironment = $test;

        // Set environment
        if ($this->isTestEnvironment) {
            $this->setEnvironment(Environments::TEST);
        } else {
            $this->setEnvironment(Environments::PRODUCTION);
        }
    }

    /**
     * Set environment
     */
    public function setEnvironment(Environments $environment): void
    {
        $this->environment = $environment->toArray();
    }

    /**
     * Get environment
     */
    public function getEnvironment(): array
    {
        return $this->environment;
    }

    /**
     * Is test environment
     */
    public function isTestEnvironment(): bool
    {
        return $this->environment['code'] == Environments::TEST->value;
    }

    /**
     * Get errors
     */
    public function getErrors(): array
    {
        $errors = [];
        if (isset($this->responseDian->ErrorMessage->string)) {
            $errorsList = $this->responseDian->ErrorMessage->string;
            $errors = (is_array($errorsList)) ? $errorsList : [$errorsList];
        }

        return $errors;
    }

    /**
     * Get status message
     */
    public function getStatusMessage(): string
    {
        return is_string($this->responseDian->StatusMessage) ? $this->responseDian->StatusMessage : '';
    }

    /**
     * Is valid
     */
    public function isValid(): bool
    {
        return filter_var($this->responseDian->IsValid, FILTER_VALIDATE_BOOLEAN);
    }
}
