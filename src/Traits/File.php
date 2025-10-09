<?php

namespace DazzaDev\SriSigner\Traits;

use DazzaDev\SriSigner\Exceptions\FileException;
use ZipArchive;

trait File
{
    /**
     * File path
     */
    protected ?string $filePath = null;

    /**
     * File name
     */
    protected ?string $fileName = null;

    /**
     * File path
     */
    protected function validateFilePath()
    {
        if (is_null($this->filePath)) {
            throw new FileException('File path is not set');
        }
    }

    /**
     * Get file path
     */
    public function getFilePath()
    {
        $this->validateFilePath();

        return $this->filePath;
    }

    /**
     * Get signed path
     */
    public function getSignedPath(): string
    {
        $this->validateFilePath();

        return $this->filePath . '/signed';
    }

    /**
     * Get generated path
     */
    public function getGeneratedPath(): string
    {
        $this->validateFilePath();

        return $this->filePath . '/generated';
    }

    /**
     * Set file path
     */
    public function setFilePath(string $filePath): void
    {
        $this->filePath = $filePath;
    }

    /**
     * Set file name
     */
    public function setFileName(): void
    {
        $this->fileName = $this->getBaseFileName();
    }

    /**
     * Get file name
     */
    public function getFileName(): string
    {
        return $this->fileName;
    }

    /**
     * Create directories
     */
    protected function createDirectories()
    {
        $filePath = $this->getFilePath();

        // Create base directory if it doesn't exist
        if (! file_exists($filePath)) {
            mkdir($filePath, 0777, true);
        }

        // Create generated directory if it doesn't exist
        if (! file_exists($filePath . '/generated')) {
            mkdir($filePath . '/generated', 0777, true);
        }

        // Create signed directory if it doesn't exist
        if (! file_exists($filePath . '/signed')) {
            mkdir($filePath . '/signed', 0777, true);
        }
    }
}
