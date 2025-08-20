<?php
namespace App\Service;

use Cloudinary\Cloudinary;
use Cloudinary\Configuration\Configuration;

class CloudinaryUploader
{
    private Cloudinary $cloudinary;

    public function __construct(string $cloudName, string $apiKey, string $apiSecret)
    {
        // Vérifier que les paramètres ne sont pas vides
        if (empty($cloudName) || empty($apiKey) || empty($apiSecret)) {
            throw new \InvalidArgumentException('Les paramètres Cloudinary ne peuvent pas être vides');
        }

        // Configuration Cloudinary
        $this->cloudinary = new Cloudinary([
            'cloud' => [
                'cloud_name' => $cloudName,
                'api_key'    => $apiKey,
                'api_secret' => $apiSecret,
            ],
            'url' => [
                'secure' => true
            ]
        ]);
    }

    public function uploadImage(string $filePath): string
    {
        $result = $this->cloudinary->uploadApi()->upload($filePath);
        return $result['secure_url'];
    }
}