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
     * Format issuer name according to SRI requirements
     */
    public function formatIssuerName(array $issuer): string
    {
        $parts = [];

        // Order according to SRI format: CN, L, OU, O, C
        if (isset($issuer['CN'])) {
            $parts[] = 'CN=' . $issuer['CN'];
        }
        if (isset($issuer['L'])) {
            $parts[] = 'L=' . $issuer['L'];
        }
        if (isset($issuer['OU'])) {
            $parts[] = 'OU=' . $issuer['OU'];
        }
        if (isset($issuer['O'])) {
            $parts[] = 'O=' . $issuer['O'];
        }
        if (isset($issuer['C'])) {
            $parts[] = 'C=' . $issuer['C'];
        }

        return implode(',', $parts);
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
}
