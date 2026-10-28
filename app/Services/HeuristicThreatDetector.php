<?php

namespace App\Services;

class HeuristicThreatDetector
{
    /**
     * Daftar brand resmi dan domain valid utama.
     *
     * @var array<string, array<int, string>>
     */
    protected array $targetedBrands = [
        'google' => ['google.com', 'google.co.id', 'google.co.uk', 'google.com.sg', 'google.de', 'google.fr', 'google.co.jp'],
        'facebook' => ['facebook.com', 'fb.com', 'fb.me'],
        'instagram' => ['instagram.com'],
        'whatsapp' => ['whatsapp.com', 'wa.me'],
        'microsoft' => ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'msn.com'],
        'apple' => ['apple.com', 'icloud.com'],
        'paypal' => ['paypal.com', 'paypal.me'],
        'netflix' => ['netflix.com'],
        'amazon' => ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp'],
        'twitter' => ['twitter.com', 'x.com'],
        'yahoo' => ['yahoo.com'],
        'linkedin' => ['linkedin.com'],
        'tiktok' => ['tiktok.com'],
        'bca' => ['bca.co.id', 'klikbca.com'],
        'mandiri' => ['bankmandiri.co.id', 'mandiri.co.id'],
        'bri' => ['bri.co.id'],
        'bni' => ['bni.co.id'],
        'dana' => ['dana.id'],
        'shopee' => ['shopee.co.id', 'shopee.com'],
        'tokopedia' => ['tokopedia.com'],
    ];

    /**
     * Pola substitusi karakter yang lazim digunakan pada serangan typosquatting/homoglyph/leetspeak.
     *
     * @var array<string, string>
     */
    protected array $substitutions = [
        '0' => 'o',
        '1' => 'l',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '8' => 'b',
        '@' => 'a',
        'vv' => 'w',
        'rn' => 'm',
    ];

    /**
     * Menganalisis URL terhadap indikasi ancaman heuristik dan typosquatting.
     *
     * @return array{threat_type: string, detail: string}|null
     */
    public function analyze(string $url): ?array
    {
        $parsed = parse_url($url);
        if (! $parsed || empty($parsed['host'])) {
            return null;
        }

        $host = strtolower($parsed['host']);

        // 1. Deteksi penyamaran kredensial URL (@ trick)
        if (! empty($parsed['user']) || str_contains($url, '@')) {
            return [
                'threat_type' => 'SOCIAL_ENGINEERING (Deceptive Authority)',
                'detail' => 'URL menyematkan karakter "@" yang berpotensi menyamarkan domain tujuan asli di mata pengguna.',
            ];
        }

        // 2. Deteksi host berupa alamat IP langsung
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [
                'threat_type' => 'SUSPICIOUS_IP_HOST',
                'detail' => "URL menggunakan alamat IP langsung ({$host}) alih-alih nama domain terdaftar.",
            ];
        }

        // 3. Deteksi serangan Homograph / Punycode (IDN)
        if (str_starts_with($host, 'xn--') || str_contains($host, '.xn--')) {
            return [
                'threat_type' => 'SOCIAL_ENGINEERING (Punycode / Homograph)',
                'detail' => 'Domain menggunakan karakter non-ASCII (Punycode) yang berpotensi memalsukan karakter alfabet domain terpercaya.',
            ];
        }

        $hostParts = explode('.', $host);
        $numParts = count($hostParts);
        if ($numParts < 2) {
            return null;
        }

        // Ambil Second-Level Domain (SLD) & domain terdaftar
        $isSecondLevelTld = in_array(implode('.', array_slice($hostParts, -2)), [
            'co.id', 'co.uk', 'com.br', 'com.sg', 'ac.id', 'go.id', 'or.id',
        ], true);

        $sldIndex = $isSecondLevelTld ? $numParts - 3 : $numParts - 2;
        if ($sldIndex < 0) {
            return null;
        }

        $registeredDomain = implode('.', array_slice($hostParts, $sldIndex));
        $sld = $hostParts[$sldIndex] ?? '';

        // 4. Analisis peniruan brand (Typosquatting & Subdomain Spoofing)
        foreach ($this->targetedBrands as $brand => $officialDomains) {
            if (in_array($registeredDomain, $officialDomains, true)) {
                continue;
            }

            // Normalisasi substitusi leetspeak (misal: g00gle -> google, paypa1 -> paypal)
            $normalizedSld = str_replace(array_keys($this->substitutions), array_values($this->substitutions), $sld);

            // A. Substitusi homoglyph / leetspeak tepat sama dengan nama brand
            if ($normalizedSld === $brand && $sld !== $brand) {
                return [
                    'threat_type' => 'SOCIAL_ENGINEERING / TYPOSQUATTING',
                    'detail' => "Domain \"{$registeredDomain}\" terindikasi Typosquatting (meniru brand resmi \"{$brand}\" dengan substitusi karakter).",
                ];
            }

            // B. Kemiripan jarak edit (Levenshtein distance)
            $lev = levenshtein($sld, $brand);
            if ($lev > 0 && $lev <= 2 && strlen($sld) >= 4) {
                return [
                    'threat_type' => 'SOCIAL_ENGINEERING / TYPOSQUATTING',
                    'detail' => "Nama domain \"{$registeredDomain}\" memiliki kemiripan mencurigakan dengan brand resmi \"{$brand}\" (jarak karakter: {$lev}).",
                ];
            }

            // C. Peniruan nama brand pada subdomain milik domain pihak ketiga
            if (str_contains($host, $brand) && ! in_array($registeredDomain, $officialDomains, true)) {
                return [
                    'threat_type' => 'SOCIAL_ENGINEERING (Brand Impersonation)',
                    'detail' => "Domain \"{$registeredDomain}\" memanfaatkan nama brand \"{$brand}\" pada struktur subdomain untuk mengelabui korban.",
                ];
            }
        }

        return null;
    }
}
