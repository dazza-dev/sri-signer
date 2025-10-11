<?php
require_once '../vendor/autoload.php';

use DazzaDev\SriXmlGenerator\XmlHelper;
use DazzaDev\SriSigner\Client;
use DazzaDev\SriXmlGenerator\Models\Invoice\Invoice;

$documentData = [
    'environment' => 1,
    "sequential" => "000000009",
    "date" => "2025-10-03",
    "currency" => "DOLAR",
];

// Company
$documentData['company'] = [
    'identification_number' => '0195127050001',
    'legal_name' => 'AURANET S.A.S.',
    'trade_name' => 'AURANET S.A.S.',
    'head_office_address' => 'Company Address',
    'establishment' => [
        'code' => '001',
        'name' => 'Main Establishment',
        'address' => 'Main Establishment',
    ],
    'emission_point' => [
        'code' => '001',
        'name' => 'Main Emission Point',
    ],
    'rimpe_regime_taxpayer' => 'GENERAL',
    "special_taxpayer_number" => null, // Contribuyente Especial
    'withholding_agent' => false, // Agente de retención
    "requires_accounting" => true, // obligado a llevar contabilidad
];

$documentData['customer'] = [
    'name' => 'JUAN PÉREZ',
    'identification_type' => '05',
    'identification_number' => '1717218912',
    'address' => 'Av. República 240',
];

// Invoice Data
//$invoice = (new Invoice($data, $accessKey))->toArray();

// XML
//$xml = (new XmlHelper)->getXml('invoice', $invoice);

// Client
$client = new Client(true);

// Set certificate
$client->setCertificate([
    'path' => __DIR__ . '/old-certificado.p12',
    'password' => '29063636',
]);

// Ruta donde se guardarán los archivos xml
$client->setFilePath(__DIR__ . '/sri');

// Send Document
$client->setDocumentType('invoice');
$client->setDocumentData($documentData);

$document = $client->sendDocument();

echo "Document saved to signed.xml successfully!";
