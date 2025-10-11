<?php

namespace DazzaDev\SriSigner\Traits;

use DazzaDev\SriSigner\CertificateValidator;
use DazzaDev\SriSigner\Exceptions\CertificateException;

trait Certificate
{
    /**
     * Certificate path
     */
    protected string $certificatePath;

    /**
     * Certificate password
     */
    protected string $certificatePassword;

    /**
     * Certificate data
     */
    protected ?array $certificateData = null;

    /**
     * Set and validate certificate
     *
     * @throws CertificateException
     */
    public function setCertificate(array $certificate): void
    {
        if (! isset($certificate['path'], $certificate['password'])) {
            throw new CertificateException('Certificate path and password are required');
        }

        $this->setCertificatePath($certificate['path']);
        $this->setCertificatePassword($certificate['password']);

        // Validate certificate
        $validator = new CertificateValidator($this->certificatePath, $this->certificatePassword);
        $this->certificateData = $validator->validate();
    }

    /**
     * Set certificate path
     */
    public function setCertificatePath(string $certificatePath): void
    {
        $this->certificatePath = $certificatePath;
    }

    /**
     * Get certificate path
     */
    public function getCertificatePath(): string
    {
        return $this->certificatePath;
    }

    /**
     * Set certificate password
     */
    public function setCertificatePassword(string $certificatePassword): void
    {
        $this->certificatePassword = $certificatePassword;
    }

    /**
     * Get certificate password
     */
    public function getCertificatePassword(): string
    {
        return $this->certificatePassword;
    }

    /**
     * Get validated certificate data
     *
     * @throws CertificateException
     */
    public function getCertificateData(): array
    {
        if ($this->certificateData === null) {
            throw new CertificateException('Certificate has not been validated yet');
        }

        return $this->certificateData;
    }


    /**
     * Get public certificate
     */
    public function getPublicCert(): string
    {
        return $this->certificateData['cert'];
    }

    /**
     * Get clean X509 certificate data without metadata for XML signing
     */
    public function getCleanX509Certificate(): string
    {
        $certPem = $this->certificateData['cert'];

        // Extract only the certificate content between BEGIN and END markers
        $pattern = '/-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s';
        if (preg_match($pattern, $certPem, $matches)) {
            // Remove any whitespace and newlines from the base64 content
            return preg_replace('/\s+/', '', $matches[1]);
        }

        throw new CertificateException('Could not extract clean X509 certificate data');
    }

    /**
     * Get X509 certificate formatted with line breaks every 76 characters for XML output
     * According to SRI documentation and RFC 2045 MIME standard
     */
    public function getFormattedX509Certificate(): string
    {
        $cleanCert = $this->getCleanX509Certificate();

        // Insert line breaks every 76 characters as per SRI documentation
        return preg_replace('/.{76}/', '$0' . "\n", $cleanCert);
    }

    /**
     * Get certificate serial number
     */
    public function getCertificateSerialNumber(): string
    {
        $certDetails = $this->getCertificateDetails();

        return $certDetails['serialNumber'];
    }

    /**
     * Get issuer name formatted according to SRI requirements
     */
    public function getIssuerName(): string
    {
        $certDetails = $this->getCertificateDetails();

        return $this->formatIssuerName($certDetails['issuer']);
    }

    /**
     * Format issuer name according to SRI requirements
     */
    public function formatIssuerName(array $issuer): string
    {
        // Convert issuer array to key-value pairs and reverse order (like JavaScript implementation)
        $issuerAttrs = [];
        foreach ($issuer as $shortName => $value) {
            $issuerAttrs[] = ['shortName' => $shortName, 'value' => $value];
        }

        // Reverse the array and map to "shortName=value" format
        $issuerName = array_map(function ($attr) {
            return $attr['shortName'] . '=' . $attr['value'];
        }, array_reverse($issuerAttrs));

        return implode(', ', $issuerName);
    }

    /**
     * Get certificate in DER binary format
     */
    public function getDerBinary(): string
    {
        return base64_decode($this->getFormattedX509Certificate());
    }

    /**
     * Get certificate details parsed from the certificate
     */
    public function getCertificateDetails(): array
    {
        $certDetails = openssl_x509_parse($this->getPublicCert());
        if ($certDetails === false) {
            throw new CertificateException('Unable to parse certificate details');
        }

        return $certDetails;
    }

    /**
     * Get private key
     */
    public function getPrivateKey(): string
    {
        return $this->certificateData['pkey'];
    }

    /**
     * Extract all private keys from P12 certificate using OpenSSL
     * Returns array of private keys with their friendly names and types
     */
    public function extractAllPrivateKeys(): array
    {
        $tempPemFile = tempnam(sys_get_temp_dir(), 'cert_keys_');
        
        try {
            // Extract all keys and certificates to temporary PEM file
            $command = sprintf(
                'openssl pkcs12 -in %s -passin pass:%s -nodes -out %s 2>/dev/null',
                escapeshellarg($this->certificatePath),
                escapeshellarg($this->certificatePassword),
                escapeshellarg($tempPemFile)
            );
            
            exec($command, $output, $returnCode);
            
            if ($returnCode !== 0) {
                throw new CertificateException('Failed to extract private keys from P12 certificate');
            }
            
            $pemContent = file_get_contents($tempPemFile);
            if ($pemContent === false) {
                throw new CertificateException('Failed to read extracted PEM content');
            }
            
            return $this->parsePrivateKeysFromPem($pemContent);
            
        } finally {
            if (file_exists($tempPemFile)) {
                unlink($tempPemFile);
            }
        }
    }

    /**
     * Parse private keys from PEM content
     * Identifies Signing Key vs Decryption Key based on friendly names
     */
    private function parsePrivateKeysFromPem(string $pemContent): array
    {
        $privateKeys = [];
        $lines = explode("\n", $pemContent);
        $currentKey = null;
        $keyContent = '';
        $inKey = false;
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            // Check for friendly name indicators
            if (strpos($line, 'friendlyName:') !== false || 
                strpos($line, 'Signing Key') !== false || 
                strpos($line, 'Decryption Key') !== false) {
                
                if (strpos($line, 'Signing Key') !== false) {
                    $currentKey = ['type' => 'signing', 'friendlyName' => $line];
                } elseif (strpos($line, 'Decryption Key') !== false) {
                    $currentKey = ['type' => 'decryption', 'friendlyName' => $line];
                } else {
                    $currentKey = ['type' => 'unknown', 'friendlyName' => $line];
                }
            }
            
            // Start of private key
            if (strpos($line, '-----BEGIN') !== false && 
                (strpos($line, 'PRIVATE KEY') !== false || strpos($line, 'RSA PRIVATE KEY') !== false)) {
                $inKey = true;
                $keyContent = $line . "\n";
                continue;
            }
            
            // End of private key
            if (strpos($line, '-----END') !== false && 
                (strpos($line, 'PRIVATE KEY') !== false || strpos($line, 'RSA PRIVATE KEY') !== false)) {
                $keyContent .= $line . "\n";
                $inKey = false;
                
                if ($currentKey !== null) {
                    $currentKey['content'] = $keyContent;
                    $privateKeys[] = $currentKey;
                } else {
                    // If no friendly name found, assume it's a signing key
                    $privateKeys[] = [
                        'type' => 'signing',
                        'friendlyName' => 'Default Private Key',
                        'content' => $keyContent
                    ];
                }
                
                $keyContent = '';
                $currentKey = null;
                continue;
            }
            
            // Collect key content
            if ($inKey) {
                $keyContent .= $line . "\n";
            }
        }
        
        return $privateKeys;
    }

    /**
     * Get the correct signing private key
     * Prioritizes keys marked as "Signing Key" over "Decryption Key"
     */
    public function getSigningPrivateKey(): string
    {
        $allKeys = $this->extractAllPrivateKeys();
        
        if (empty($allKeys)) {
            // Fallback to standard method if no keys found
            return $this->getPrivateKey();
        }
        
        // Look for signing key first
        foreach ($allKeys as $key) {
            if ($key['type'] === 'signing') {
                return $key['content'];
            }
        }
        
        // If no signing key found, use the first available key
        return $allKeys[0]['content'];
    }

    /**
     * Validate that the signing private key works correctly
     * Tests the key by attempting to sign a small test string
     */
    public function validateSigningKey(string $privateKeyContent): bool
    {
        try {
            $testData = 'test_signature_validation';
            $privateKey = openssl_pkey_get_private($privateKeyContent, $this->certificatePassword);
            
            if ($privateKey === false) {
                return false;
            }
            
            $signature = '';
            $result = openssl_sign($testData, $signature, $privateKey, OPENSSL_ALGO_SHA1);
            
            return $result !== false;
            
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Validate certificate dates
     * Throws exception if certificate has expired or is not yet valid
     */
    public function validateCertificateDates(): void
    {
        $certDetails = $this->getCertificateDetails();

        // Get certificate validity dates
        $notBefore = $certDetails['validFrom_time_t'];
        $notAfter = $certDetails['validTo_time_t'];
        $currentDate = time();

        if ($currentDate < $notBefore || $currentDate > $notAfter) {
            throw new CertificateException('Invalid certificate, certificate has expired');
        }
    }

    /**
     * Check if certificate is currently valid (non-throwing version)
     * Returns true if certificate is valid, false otherwise
     */
    public function isCertificateValid(): bool
    {
        try {
            $this->validateCertificateDates();
            return true;
        } catch (CertificateException $e) {
            return false;
        }
    }

    /**
     * Get certificate validity information
     * Returns detailed information about certificate dates
     */
    public function getCertificateValidity(): array
    {
        $certDetails = $this->getCertificateDetails();
        $currentDate = time();

        return [
            'notBefore' => $certDetails['validFrom_time_t'],
            'notAfter' => $certDetails['validTo_time_t'],
            'currentDate' => $currentDate,
            'isValid' => $this->isCertificateValid(),
            'notBeforeFormatted' => date('Y-m-d H:i:s', $certDetails['validFrom_time_t']),
            'notAfterFormatted' => date('Y-m-d H:i:s', $certDetails['validTo_time_t']),
            'currentDateFormatted' => date('Y-m-d H:i:s', $currentDate)
        ];
    }
}
