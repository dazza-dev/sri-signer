# SRI Signer 🇪🇨

Paquete para firmar XML de documentos electrónicos (Factura, Guía de remisión, Nota crédito, Nota débito y Comprobante de retención) basado en las especificaciones del Servicio de Rentas Internas (SRI) de Ecuador.

## Instalación

```bash
composer require dazza-dev/sri-signer
```

## Guía de uso

```php
use DazzaDev\SriSigner\Signer;

// Instanciar el signer
$signer = new Signer(
    certificatePath: __DIR__ . '/certificado.p12',
    certificatePassword: 'clave_certificado',
);

// XML como string o DOMDocument
$xmlString = file_get_contents(__DIR__ . '/factura.xml');

// Cargar el XML en el signer
$signer->loadXML($xmlString);

// Firmar el XML
$signedXML = $signer->sign();
```

## Notas importantes sobre la estructura del XML

- El documento XML a firmar debe contener únicamente el nodo raíz (por ejemplo: `factura`, `notaCredito`, `notaDebito`) con su atributo `id="comprobante"`, el atributo `version` correspondiente, y sus elementos hijos que describen el contenido del documento, sin incluir otros namespaces adicionales.

```xml
 <?xml version="1.0" encoding="UTF-8"?>
 <factura Id="comprobante" version="1.1.0">
  <infoTributaria>...</infoTributaria>
  <infoFactura>...</infoFactura>
  <detalles>...</detalles>
 <factura>
```

- La factura debe estar en formato UTF-8.
- Sin namespaces (xmlns).

```xml
<factura
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  id="comprobante"
  version="2.1.0"
>
...
</factura>
```

En este ejemplo, el xmlns:ds="..." debe ser eliminado. Como contexto, ningún namespace es necesario para la factura en sí. Este paquete se encarga de colocar los namespaces necesarios en la firma digital generada.

## Nota importante sobre los certificados

El paquete se ha probado satisfactoriamente usando certificados .p12 de estos proveedores:

- Uanataca.
- Security Data.

Si pruebas el paquete con .p12 de otros proveedores y encuentras problemas, por favor crea un [issue](https://github.com/dazza-dev/sri-signer/issues)

## Envio de XML firmado

Una vez firmado el XML, puedes enviarlo al SRI usando el paquete [SRI Sender](https://github.com/dazza-dev/sri-sender).

## Generar XML

Si necesitas generar un XML para firmar, puedes usar el paquete [SRI XML Generator](https://github.com/dazza-dev/sri-xml-generator).

## Contribuciones

Contribuciones son bienvenidas. Si encuentras algún error o tienes ideas para mejoras, por favor abre un issue o envía un pull request. Asegúrate de seguir las guías de contribución.

## Autor

SRI Signer fue creado por [DAZZA](https://github.com/dazza-dev).

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](https://opensource.org/licenses/MIT).
