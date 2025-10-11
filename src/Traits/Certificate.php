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
        return base64_decode($this->getCleanX509Certificate());
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
