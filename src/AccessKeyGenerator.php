<?php

namespace DazzaDev\SriSigner;

use Exception;
use InvalidArgumentException;

class AccessKeyGenerator
{
    // Constants for validation and calculation
    private const SEQUENTIAL_LENGTH = 9;
    private const NUMERIC_CODE_MIN = 10000000;
    private const NUMERIC_CODE_MAX = 99999999;
    private const VERIFICATION_STRING_LENGTH = 48;
    private const EMISSION_TYPE = '1';
    private const DEFAULT_ESTABLISHMENT = '001';
    private const DEFAULT_EMISSION_POINT = '001';
    private const MODULUS = 11;
    private const MIN_MULTIPLIER = 2;
    private const MAX_MULTIPLIER = 7;

    /**
     * Generate an access key for the SRI XML
     *
     * @param array $data Array containing the required data for access key generation
     *                   - fechaEmision: Emission date (string)
     *                   - ruc: RUC number (string)
     *                   - codDoc: Document type code (string)
     *                   - ambiente: Environment type (string)
     *                   - secuencial: Sequential number (string|int)
     *                   - estab: Establishment code (optional, defaults to '001')
     *                   - ptoEmi: Emission point code (optional, defaults to '001')
     * @return string The generated access key
     * @throws InvalidArgumentException When required data is missing or invalid
     * @throws Exception When access key generation fails
     */
    public static function generate(array $data): string
    {
        try {
            self::validateRequiredData($data);

            $formattedDate = self::formatEmissionDate($data['fechaEmision']);
            $ruc = $data['ruc'];
            $documentType = $data['codDoc'];
            $environment = $data['ambiente'];
            $series = self::buildSeries($data);
            $sequential = self::formatSequential($data['secuencial']);
            $numericCode = self::generateNumericCode();

            $verificationString = self::buildVerificationString(
                $formattedDate,
                $documentType,
                $ruc,
                $environment,
                $series,
                $sequential,
                $numericCode
            );

            $verificationDigit = self::calculateVerificationDigit($verificationString);

            return $verificationString . $verificationDigit;
        } catch (Exception $e) {
            throw new Exception('Failed to generate access key: ' . $e->getMessage());
        }
    }

    /**
     * Validate that all required data is present and valid
     *
     * @param array $data The input data array
     * @throws InvalidArgumentException When required data is missing or invalid
     */
    private static function validateRequiredData(array $data): void
    {
        $requiredFields = ['fechaEmision', 'ruc', 'codDoc', 'ambiente', 'secuencial'];

        foreach ($requiredFields as $field) {
            if (!isset($data[$field]) || empty($data[$field])) {
                throw new InvalidArgumentException("Required field '{$field}' is missing or empty");
            }
        }

        // Validate RUC format (should be 13 digits)
        if (!preg_match('/^\d{13}$/', $data['ruc'])) {
            throw new InvalidArgumentException('RUC must be exactly 13 digits');
        }

        // Validate sequential is numeric
        if (!is_numeric($data['secuencial'])) {
            throw new InvalidArgumentException('Sequential must be numeric');
        }
    }

    /**
     * Format the emission date to dmY format
     *
     * @param string $date The emission date
     * @return string Formatted date
     * @throws InvalidArgumentException When date format is invalid
     */
    private static function formatEmissionDate(string $date): string
    {
        $timestamp = strtotime($date);
        if ($timestamp === false) {
            throw new InvalidArgumentException('Invalid date format for fechaEmision');
        }

        return date('dmY', $timestamp);
    }

    /**
     * Build the series code from establishment and emission point
     *
     * @param array $data The input data array
     * @return string The series code
     */
    private static function buildSeries(array $data): string
    {
        $establishment = $data['estab'] ?? self::DEFAULT_ESTABLISHMENT;
        $emissionPoint = $data['ptoEmi'] ?? self::DEFAULT_EMISSION_POINT;

        return $establishment . $emissionPoint;
    }

    /**
     * Format the sequential number with leading zeros
     *
     * @param string|int $sequential The sequential number
     * @return string Formatted sequential number
     */
    private static function formatSequential($sequential): string
    {
        return str_pad((string)$sequential, self::SEQUENTIAL_LENGTH, '0', STR_PAD_LEFT);
    }

    /**
     * Build the verification string by concatenating all components
     *
     * @param string $date Formatted emission date
     * @param string $documentType Document type code
     * @param string $ruc RUC number
     * @param string $environment Environment type
     * @param string $series Series code
     * @param string $sequential Sequential number
     * @param int $numericCode Generated numeric code
     * @return string The verification string
     */
    private static function buildVerificationString(
        string $date,
        string $documentType,
        string $ruc,
        string $environment,
        string $series,
        string $sequential,
        int $numericCode
    ): string {
        return $date . $documentType . $ruc . $environment . $series . $sequential . $numericCode . self::EMISSION_TYPE;
    }

    /**
     * Calculate the verification digit using the modulus 11 algorithm
     *
     * @param string $verificationString The verification string
     * @return int The verification digit
     */
    private static function calculateVerificationDigit(string $verificationString): int
    {
        $multiplier = self::MIN_MULTIPLIER;
        $sum = 0;

        for ($i = self::VERIFICATION_STRING_LENGTH - 1; $i >= 0; $i--) {
            if ($multiplier > self::MAX_MULTIPLIER) {
                $multiplier = self::MIN_MULTIPLIER;
            }

            $sum += (int)$verificationString[$i] * $multiplier;
            $multiplier++;
        }

        $remainder = $sum % self::MODULUS;
        $verificationDigit = $remainder === 0 ? 0 : self::MODULUS - $remainder;

        // Special case: if verification digit is 10, use 1 instead
        return $verificationDigit === 10 ? 1 : $verificationDigit;
    }

    /**
     * Generate a random 8-digit numeric code
     *
     * @return int Random 8-digit numeric code
     */
    private static function generateNumericCode(): int
    {
        return rand(self::NUMERIC_CODE_MIN, self::NUMERIC_CODE_MAX);
    }
}
