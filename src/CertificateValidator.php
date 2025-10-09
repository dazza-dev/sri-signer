<?php

namespace DazzaDev\SriSigner;

use Exception;
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
        $cliValidation = $this->validateCertificateWithCLI($certificateContent);
        if (! $cliValidation['success']) {
            throw new CertificateCliException($cliValidation['error']);
        }

        // Try with legacy support
        $this->certificate = $this->readPkcs12WithLegacySupport($certificateContent);

        // Check if legacy support was successful
        if (! $this->certificate) {
            throw new CertificateException('Legacy support failed to read certificate.');
        }

        return $this->certificate;
    }

    /**
     * Validate certificate using OpenSSL CLI
     */
    private function validateCertificateWithCLI(string $certificateContent): array
    {
        try {
            // Create temporary file
            $tempFile = tempnam(sys_get_temp_dir(), 'cert_validation_') . '.p12';
            file_put_contents($tempFile, $certificateContent);

            // Command to get certificate info
            $infoCommand = sprintf(
                'openssl pkcs12 -info -in %s -passin pass:%s -noout 2>&1',
                escapeshellarg($tempFile),
                escapeshellarg($this->certificatePassword)
            );

            $output = shell_exec($infoCommand);

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
     * Alternative method to read PKCS12 with legacy support using command line
     */
    private function readPkcs12WithLegacySupport(string $certificateContent): bool
    {
        $passwords = [
            $this->certificatePassword,
            trim($this->certificatePassword),
            utf8_encode($this->certificatePassword),
            utf8_decode($this->certificatePassword)
        ];

        foreach ($passwords as $index => $password) {
            // Create temporary file for certificate
            $tempCertFile = tempnam(sys_get_temp_dir(), 'cert_') . '.p12';
            file_put_contents($tempCertFile, $certificateContent);

            try {
                // Extract certificate and private key using legacy providers
                $certPem = $this->extractCertificateWithLegacy($tempCertFile, $password);
                $keyPem = $this->extractPrivateKeyWithLegacy($tempCertFile, $password);

                // Create compatible data structure
                if ($certPem && $keyPem) {
                    $certData = ['cert' => $certPem, 'pkey' => $keyPem];
                    unlink($tempCertFile);
                    $this->certificate = $certData;

                    return true;
                }

                // Try modern conversion if legacy failed
                $modernCertPath = $this->convertToModernPkcs12($tempCertFile, $password);
                if ($modernCertPath) {
                    $modernContent = file_get_contents($modernCertPath);
                    $certData = [];

                    if (openssl_pkcs12_read($modernContent, $certData, $password)) {
                        unlink($tempCertFile);
                        unlink($modernCertPath);
                        $this->certificate = $certData;

                        return true;
                    }

                    unlink($modernCertPath);
                }
            } catch (\Exception $e) {
                throw new CertificateException("Error en método CLI: " . $e->getMessage());
            } finally {
                if (file_exists($tempCertFile)) {
                    unlink($tempCertFile);
                }
            }
        }

        return false;
    }

    /**
     * Extrae el certificado usando proveedores legacy
     */
    private function extractCertificateWithLegacy($certFile, $password)
    {
        $commands = [
            // Comando con proveedores legacy explícitos
            sprintf(
                'openssl pkcs12 -in %s -clcerts -nokeys -passin pass:%s -provider legacy -provider default 2>/dev/null',
                escapeshellarg($certFile),
                escapeshellarg($password)
            ),

            // Comando tradicional
            sprintf(
                'openssl pkcs12 -in %s -clcerts -nokeys -passin pass:%s 2>/dev/null',
                escapeshellarg($certFile),
                escapeshellarg($password)
            ),

            // Comando con configuración legacy temporal
            sprintf(
                'OPENSSL_CONF="" openssl pkcs12 -in %s -clcerts -nokeys -passin pass:%s -legacy 2>/dev/null',
                escapeshellarg($certFile),
                escapeshellarg($password)
            )
        ];

        foreach ($commands as $command) {
            $output = shell_exec($command);
            if ($output && strpos($output, 'BEGIN CERTIFICATE') !== false) {
                echo "Certificado extraído exitosamente" . PHP_EOL;
                return $output;
            }
        }

        return false;
    }

    /**
     * Extrae la clave privada usando proveedores legacy
     */
    private function extractPrivateKeyWithLegacy(string $certFile, string $password)
    {
        $commands = [
            // Comando con proveedores legacy explícitos
            sprintf(
                'openssl pkcs12 -in %s -nocerts -nodes -passin pass:%s -provider legacy -provider default 2>/dev/null',
                escapeshellarg($certFile),
                escapeshellarg($password)
            ),

            // Comando tradicional
            sprintf(
                'openssl pkcs12 -in %s -nocerts -nodes -passin pass:%s 2>/dev/null',
                escapeshellarg($certFile),
                escapeshellarg($password)
            ),

            // Comando con configuración legacy temporal
            sprintf(
                'OPENSSL_CONF="" openssl pkcs12 -in %s -nocerts -nodes -passin pass:%s -legacy 2>/dev/null',
                escapeshellarg($certFile),
                escapeshellarg($password)
            )
        ];

        foreach ($commands as $command) {
            $output = shell_exec($command);
            if ($output && (strpos($output, 'BEGIN PRIVATE KEY') !== false ||
                strpos($output, 'BEGIN RSA PRIVATE KEY') !== false)) {
                echo "Clave privada extraída exitosamente" . PHP_EOL;
                return $output;
            }
        }

        return false;
    }

    /**
     * Convierte el certificado PKCS12 a un formato más moderno
     */
    private function convertToModernPkcs12($oldCertFile, $password)
    {
        try {
            $tempPemFile = tempnam(sys_get_temp_dir(), 'cert_pem_') . '.pem';
            $modernCertFile = tempnam(sys_get_temp_dir(), 'cert_modern_') . '.p12';

            // Paso 1: Convertir a PEM con proveedores legacy
            $convertToPemCommand = sprintf(
                'openssl pkcs12 -in %s -out %s -nodes -passin pass:%s -provider legacy -provider default 2>/dev/null',
                escapeshellarg($oldCertFile),
                escapeshellarg($tempPemFile),
                escapeshellarg($password)
            );

            $result1 = shell_exec($convertToPemCommand);

            if (file_exists($tempPemFile) && filesize($tempPemFile) > 0) {
                // Paso 2: Convertir de vuelta a PKCS12 con algoritmos modernos
                $convertToPkcs12Command = sprintf(
                    'openssl pkcs12 -export -in %s -out %s -passout pass:%s -keypbe AES-256-CBC -certpbe AES-256-CBC 2>/dev/null',
                    escapeshellarg($tempPemFile),
                    escapeshellarg($modernCertFile),
                    escapeshellarg($password)
                );

                $result2 = shell_exec($convertToPkcs12Command);

                if (file_exists($modernCertFile) && filesize($modernCertFile) > 0) {
                    echo "Conversión a formato moderno exitosa" . PHP_EOL;
                    unlink($tempPemFile);
                    return $modernCertFile;
                }
            }

            // Limpiar archivos temporales si algo falló
            if (file_exists($tempPemFile)) unlink($tempPemFile);
            if (file_exists($modernCertFile)) unlink($modernCertFile);
        } catch (\Exception $e) {
            echo "Error en conversión a formato moderno: " . $e->getMessage() . PHP_EOL;
        }

        return false;
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
