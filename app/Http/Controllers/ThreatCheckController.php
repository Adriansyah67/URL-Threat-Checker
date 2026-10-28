<?php

namespace App\Http\Controllers;

use App\Services\HeuristicThreatDetector;
use Composer\CaBundle\CaBundle;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

class ThreatCheckController extends Controller
{
    public function __construct(
        protected HeuristicThreatDetector $heuristicDetector
    ) {}

    /**
     * Check URL against Heuristics & Google Safe Browsing API.
     */
    public function check(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'url' => ['required', 'url'],
        ]);

        $targetUrl = $validated['url'];
        $apiKey = config('services.google_safe_browsing.key', env('GOOGLE_SAFE_BROWSING_API_KEY'));

        if (empty($apiKey)) {
            return response()->json([
                'success' => false,
                'message' => 'Google Safe Browsing API key belum dikonfigurasi di file .env (GOOGLE_SAFE_BROWSING_API_KEY).',
            ], 500);
        }

        try {
            // 1. Analisis Heuristik (Typosquatting, Homoglyph, Deceptive Domain)
            $heuristicThreat = $this->heuristicDetector->analyze($targetUrl);

            // 2. Query ke Google Safe Browsing API v4
            $caBundlePath = class_exists(CaBundle::class) ? CaBundle::getSystemCaRootBundlePath() : true;

            $response = Http::withOptions([
                'verify' => $caBundlePath,
            ])->post("https://safebrowsing.googleapis.com/v4/threatMatches:find?key={$apiKey}", [
                'client' => [
                    'clientId' => 'url-threat-checker',
                    'clientVersion' => '1.0.0',
                ],
                'threatInfo' => [
                    'threatTypes' => [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION',
                    ],
                    'platformTypes' => ['ANY_PLATFORM'],
                    'threatEntryTypes' => ['URL'],
                    'threatEntries' => [
                        ['url' => $targetUrl],
                    ],
                ],
            ]);

            if ($response->failed()) {
                $errorData = $response->json();
                $errorMessage = $errorData['error']['message'] ?? 'Gagal menghubungi Google Safe Browsing API.';

                Log::warning('Google Safe Browsing API request failed', [
                    'url' => $targetUrl,
                    'status' => $response->status(),
                    'error' => $errorData,
                ]);

                return response()->json([
                    'success' => false,
                    'message' => $errorMessage,
                    'error' => $errorData,
                ], $response->status());
            }

            $matches = $response->json('matches', []);
            $gsbThreat = ! empty($matches);

            $isSafe = true;
            $threatType = null;
            $threatDetail = null;

            if ($heuristicThreat) {
                $isSafe = false;
                $threatType = $heuristicThreat['threat_type'];
                $threatDetail = $heuristicThreat['detail'];
            }

            if ($gsbThreat) {
                $isSafe = false;
                $gsbTypes = collect($matches)->pluck('threatType')->unique()->implode(', ');
                $threatType = $threatType ? "{$threatType}, {$gsbTypes}" : $gsbTypes;
                $threatDetail = $threatDetail
                    ? "{$threatDetail} Selain itu, URL ini terdaftar dalam database ancaman Google Safe Browsing."
                    : 'URL terdaftar sebagai ancaman aktif pada database Google Safe Browsing.';
            }

            // Simpan riwayat scan ke database
            DB::table('scan_logs')->insert([
                'url' => $targetUrl,
                'is_safe' => $isSafe,
                'threat_type' => $threatType,
                'created_at' => now(),
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'url' => $targetUrl,
                    'is_safe' => $isSafe,
                    'threat_type' => $threatType,
                    'threat_detail' => $threatDetail,
                    'matches' => $matches,
                ],
            ]);

        } catch (Throwable $e) {
            Log::error('Error during threat scanning', [
                'url' => $targetUrl,
                'exception' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Terjadi kesalahan saat memproses pemeriksaan URL: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}
