import fs from "fs";
import { signInvoiceXml } from "ec-sri-invoice-signer";
/* Puedes user require() si usas módulos commonJS. */

/* El XML del documento a firmarse. */
const invoiceXml = fs.readFileSync("factura.xml").toString();

/* El contenido del archivo pkcs12 (.p12/.pfx extension) del firmante representado como Node Buffer o string base64.
En este caso es un Node Buffer. */
const p12FileData = fs.readFileSync("signature.p12");

/* Firma la factura. Si no se pasa la opción pkcs12Password, '' será usada como contraseña. */
const signedInvoice = signInvoiceXml(invoiceXml, p12FileData, {
  pkcs12Password: "29063636",
});

// Output the signed invoice to a file
fs.writeFileSync("signed_invoice.xml", signedInvoice);
console.log("Signed invoice written to signed_invoice.xml");

//
