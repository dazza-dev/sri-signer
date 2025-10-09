<?php

namespace DazzaDev\SriSigner;

use DazzaDev\SriSigner\Actions\Document;
use DazzaDev\SriSigner\Traits\Certificate;
use DazzaDev\SriSigner\Traits\File;
use DazzaDev\SriSigner\Traits\Listing;
use DazzaDev\SriSigner\Traits\Signer;
use DazzaDev\SriSigner\Traits\Sender;
use DazzaDev\SriXmlGenerator\Enums\Environments;
use DazzaDev\SriXmlGenerator\Models\Invoice\Invoice;

class Client
{
    use Certificate;
    use Document;
    use File;
    use Listing;
    use Signer;
    use Sender;

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
     * Response Recepcion
     */
    private $responseRecepcion;

    /**
     * Response Autorizacion
     */
    private $responseAutorizacion;

    /**
     * Access key
     */
    public string $accessKey;

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
     * Get access key
     */
    public function getAccessKey(): string
    {
        return $this->accessKey;
    }

    /**
     * Get recepcion messages
     */
    public function getRecepcionMessages(string $format = 'array'): array|string
    {
        $messages = [];
        if (isset($this->responseRecepcion->RespuestaRecepcionComprobante->comprobantes)) {
            foreach ($this->responseRecepcion->RespuestaRecepcionComprobante->comprobantes as $comprobante) {
                foreach ($comprobante->mensajes as $message) {
                    //  Get message details
                    $type = $comprobante->tipo ?? 'ERROR';
                    $code = $message->identificador ?? '0';
                    $message = $message->mensaje ?? 'Error en recepción';
                    $additionalInfo = $message->informacionAdicional ?? null;

                    //  Add message to array
                    if ($format == 'array') {
                        $formattedMessage = [
                            'type' => $type,
                            'code' => $code,
                            'message' => $message,
                            'additionalInfo' => $additionalInfo,
                        ];
                    } else {
                        $formattedMessage = $type . ' ' . $code . ': ' . $message . ' ' . $additionalInfo;
                    }

                    $messages[] = $formattedMessage;
                }
            }
        }

        return $messages;
    }

    /**
     * Get recepcion status
     */
    public function getRecepcionStatus(): ?string
    {
        return $this->responseRecepcion->RespuestaRecepcionComprobante->estado ?? null;
    }
}
