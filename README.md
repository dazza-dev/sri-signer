# SRI Signer

Paquete para firmar y enviar documentos electrónicos (Facturas, Notas Crédito y Notas Débito) al SRI (Ecuador).

## Instalación

```bash
composer require dazza-dev/sri-signer
```

## Configuración

```php
use DazzaDev\SriSigner\Client;

$client = new Client(test: true); // true or false

$client->setCertificate([
    'path' => _DIR_ . '/certificado.p12',
    'password' => 'clave_certificado',
]);

// Ruta donde se guardarán los archivos xml
$client->setFilePath(_DIR_ . '/sri');
```

## Uso

### Enviar un documento electrónico (factura, nota de débito o nota de crédito)

La estructura de los datos de la factura la puedes encontrar en: [dazza-dev/sri-xml-generator](https://github.com/dazza-dev/sri-xml-generator).

```php
$client->setDocumentType('invoice'); // Tipo de documento ('invoice', 'support-document', 'debit-note', 'credit-note')
$client->setDocumentData($documentData); // Datos del documento

$document = $client->sendDocument();
```

### Obtener los listados

el SRI tiene una lista de códigos que este paquete te pone a disposición para facilitar el trabajo de consultar esto en el anexo técnico del SRI:

```php
$listings = $client->getListings();
$listingByType = $client->getListing('identification-types');
```

## Contribuciones

Contribuciones son bienvenidas. Si encuentras algún error o tienes ideas para mejoras, por favor abre un issue o envía un pull request. Asegúrate de seguir las guías de contribución.

## Autor

SRI Signer fue creado por [DAZZA](https://github.com/dazza-dev).

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](https://opensource.org/licenses/MIT).
