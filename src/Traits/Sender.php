<?php

namespace DazzaDev\SriSigner\Traits;

use Exception;
use SoapClient;
use SoapFault;

trait Sender
{
    /**
     * Validate signed XML
     */
    public function validate(string $signedXml)
    {
        try {
            $recepcionWSDL = 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl';

            $client = new SoapClient($recepcionWSDL, [
                'trace' => 1,
                'cache_wsdl' => WSDL_CACHE_NONE,
                'user_agent' => 'SOAP Client',
                'connection_timeout' => 180,
                'default_socket_timeout' => 180
            ]);

            $response = $client->validarComprobante([
                'xml' => base64_encode($signedXml)
            ]);

            $status = $response->RespuestaRecepcionComprobante->estado ?? null;

            if ($status !== 'RECIBIDA') {
                // Extract the first error message from the SRI
                $message = $response->RespuestaRecepcionComprobante->comprobantes->comprobante->mensajes->mensaje ?? null;

                $code = $message->identificador ?? '0';
                $description = $message->mensaje ?? 'Error en recepción';
                //$additionalInfo = $message->informacionAdicional ?? null;

                throw new Exception($code . ': ' . $description);
            }

            return [
                'success' => true,
                'response' => $response
            ];
        } catch (SoapFault $e) {
            throw new Exception('Error de conexión con el SRI: ' . $e->getMessage());
        }
    }

    /**
     * Authorize XML with access key
     */
    public function authorize(string $accessKey)
    {
        //
    }
}
