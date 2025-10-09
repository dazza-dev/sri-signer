<?php

namespace DazzaDev\SriSigner\Traits;

use Exception;
use SoapClient;
use SoapFault;

trait Sender
{
    /**
     * Get reception WSDL URL based on environment
     */
    private function getRecepcionWsdlUrl(): string
    {
        if ($this->isTestEnvironment()) {
            return 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl';
        }

        return 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl';
    }

    /**
     * Get authorization WSDL URL based on environment
     */
    private function getAutorizacionWsdlUrl(): string
    {
        if ($this->isTestEnvironment()) {
            return 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl';
        }

        return 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl';
    }

    /**
     * Validate signed XML
     */
    public function validate(string $signedXml): array
    {
        try {
            $client = new SoapClient($this->getRecepcionWsdlUrl(), [
                'trace' => 1,
                'cache_wsdl' => WSDL_CACHE_NONE,
                'user_agent' => 'SOAP Client',
                'connection_timeout' => 180,
                'default_socket_timeout' => 180
            ]);

            $this->responseRecepcion = $client->validarComprobante([
                'xml' => $signedXml
            ]);

            // Check if the status is not 'RECIBIDA'
            if ($this->getRecepcionStatus() !== 'RECIBIDA') {
                throw new Exception(implode("\n", $this->getRecepcionMessages('string')));
            }

            return [
                'success' => true,
                'response' => $this->responseRecepcion
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        } catch (SoapFault $e) {
            return [
                'success' => false,
                'error' => 'Error de conexión con el SRI: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Authorize XML with access key
     */
    public function authorize(string $accessKey)
    {
        try {
            $client = new SoapClient($this->getAutorizacionWsdlUrl());

            $maxIntentos = 5;
            $intentos = 0;
            while ($intentos < $maxIntentos) {
                try {
                    $intentos++;
                    $response = $client->autorizacionComprobante([
                        'claveAccesoComprobante' => $accessKey
                    ]);

                    print_r($response);

                    $autorizaciones = $response->RespuestaAutorizacionComprobante->autorizaciones->autorizacion ?? null;

                    if ($autorizaciones) {
                        $autorizacion = is_array($autorizaciones) ? $autorizaciones[0] : $autorizaciones;

                        if ($autorizacion->estado === 'AUTORIZADO') {
                            return [
                                'success' => true,
                                'autorizacion' => $autorizacion,
                                'mensajes' => $autorizacion->mensajes ?? null
                            ];
                        }

                        $message = $autorizacion->mensajes->mensaje ?? null;
                        $code = $message->identificador ?? '0';
                        $description = $message->mensaje ?? 'Comprobante no autorizado';
                        $additionalInfo = $message->informacionAdicional ?? null;

                        throw new Exception($code . ': ' . $description . ' ' . $additionalInfo);
                    }

                    sleep(1); // Espera antes del siguiente intento
                } catch (SoapFault $e) {
                    throw new Exception('Error de conexión con el SRI: ' . $e->getMessage());
                } catch (Exception $e) {
                    if ($intentos >= $maxIntentos) {
                        throw new Exception('Error inesperado en autorización: ' . $e->getMessage());
                    }
                    sleep(1);
                }
            }

            throw new Exception('No se recibió una respuesta de autorización válida del SRI después de varios intentos.');
        } catch (SoapFault $e) {
            throw new Exception('Error de conexión con el SRI: ' . $e->getMessage());
        }
    }
}
