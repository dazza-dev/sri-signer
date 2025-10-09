<?php

namespace DazzaDev\SriSigner;

use DazzaDev\SriSigner\Exceptions\CertificateException;
use DazzaDev\SriSigner\Exceptions\CertificateCliException;

class CertificateValidator
{
    /**
     * Certificate file
     */
    protected string $certificatePath;

    /**
     * Certificate password
     */
    protected string $certificatePassword;

    /**
     * Certificate data
     */
    protected ?array $certificate = null;

    /**
     * Constructor
     */
    public function __construct(string $certificatePath, string $certificatePassword)
    {
        $this->certificatePath = $certificatePath;
        $this->certificatePassword = $certificatePassword;
    }

    /**
     * Validate and load certificate
     *
     * @throws CertificateException
     */
    public function validate(): array
    {
        // Check if file exists
        if (! file_exists($this->certificatePath)) {
            throw new CertificateException('Certificate file not found at: ' . $this->certificatePath);
        }

        // Read certificate file
        $certificateContent = file_get_contents($this->certificatePath);
        if ($certificateContent === false) {
            throw new CertificateException('Could not read certificate file');
        }

        // Validate certificate with CLI before loading with PHP
        $cliValidation = $this->validateCertificateWithCLI($certificateContent, $this->certificatePassword);
        if (! $cliValidation['success']) {
            throw new CertificateCliException($cliValidation['error']);
        }

        // Validate certificate
        /*if (! openssl_pkcs12_read($certificateContent, $this->certificate, $this->certificatePassword)) {
            $error = openssl_error_string() ?: 'Certificate could not be read';
            throw new CertificateException($error);
        }*/

        return $this->certificate;
    }

    /**
     * Validate certificate using OpenSSL CLI
     */
    private function validateCertificateWithCLI(string $certificateContent, string $password): array
    {
        try {
            // Create temporary file
            $tempFile = tempnam(sys_get_temp_dir(), 'cert_validation_') . '.p12';
            file_put_contents($tempFile, $certificateContent);

            // Command to get certificate info
            $infoCommand = sprintf(
                'openssl pkcs12 -info -in %s -passin pass:%s -noout 2>&1',
                escapeshellarg($tempFile),
                escapeshellarg($password)
            );

            $output = shell_exec($infoCommand);

            echo 'OpenSSL CLI Output: ' . $output . PHP_EOL;

            // Check for specific errors
            if (strpos($output, 'MAC verify failure') !== false) {
                throw new CertificateCliException("Error: Contraseña incorrecta (MAC verify failure)");
            } elseif (strpos($output, 'unable to load') !== false) {
                throw new CertificateCliException("Error: No se puede cargar el certificado");
            } elseif (strpos($output, 'unsupported') !== false) {
                throw new CertificateCliException("Advertencia: Algoritmos no soportados detectados");
            }

            unlink($tempFile);

            return [
                'success' => true,
                'output' => $output
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => "Error en validación CLI: " . $e->getMessage()
            ];
        }
    }

    /**
     * Get the loaded certificate data
     *
     * @throws CertificateException
     */
    public function getCertificate(): array
    {
        if (! isset($this->certificate)) {
            throw new CertificateException('Certificate has not been validated yet');
        }

        return $this->certificate;
    }
}
