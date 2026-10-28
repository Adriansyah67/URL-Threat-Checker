<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class ThreatCheckTest extends TestCase
{
    use RefreshDatabase;

    public function test_it_validates_url_is_required_and_valid(): void
    {
        $response = $this->postJson('/api/check-url', [
            'url' => 'not-a-valid-url',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['url']);
    }

    public function test_it_detects_safe_url_and_logs_to_database(): void
    {
        config(['services.google_safe_browsing.key' => 'fake-api-key']);

        Http::fake([
            'https://safebrowsing.googleapis.com/*' => Http::response([], 200),
        ]);

        $response = $this->postJson('/api/check-url', [
            'url' => 'https://www.google.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'url' => 'https://www.google.com',
                    'is_safe' => true,
                    'threat_type' => null,
                ],
            ]);

        $this->assertDatabaseHas('scan_logs', [
            'url' => 'https://www.google.com',
            'is_safe' => 1,
            'threat_type' => null,
        ]);
    }

    public function test_it_detects_typosquatting_threat_like_g00gle(): void
    {
        config(['services.google_safe_browsing.key' => 'fake-api-key']);

        Http::fake([
            'https://safebrowsing.googleapis.com/*' => Http::response([], 200),
        ]);

        $response = $this->postJson('/api/check-url', [
            'url' => 'https://g00gle.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'url' => 'https://g00gle.com',
                    'is_safe' => false,
                    'threat_type' => 'SOCIAL_ENGINEERING / TYPOSQUATTING',
                ],
            ]);

        $this->assertDatabaseHas('scan_logs', [
            'url' => 'https://g00gle.com',
            'is_safe' => 0,
            'threat_type' => 'SOCIAL_ENGINEERING / TYPOSQUATTING',
        ]);
    }

    public function test_it_detects_threat_url_from_google_safe_browsing(): void
    {
        config(['services.google_safe_browsing.key' => 'fake-api-key']);

        Http::fake([
            'https://safebrowsing.googleapis.com/*' => Http::response([
                'matches' => [
                    [
                        'threatType' => 'MALWARE',
                        'platformType' => 'ANY_PLATFORM',
                        'threatEntryType' => 'URL',
                    ],
                ],
            ], 200),
        ]);

        $response = $this->postJson('/api/check-url', [
            'url' => 'https://unknown-malware-site.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'url' => 'https://unknown-malware-site.com',
                    'is_safe' => false,
                    'threat_type' => 'MALWARE',
                ],
            ]);

        $this->assertDatabaseHas('scan_logs', [
            'url' => 'https://unknown-malware-site.com',
            'is_safe' => 0,
            'threat_type' => 'MALWARE',
        ]);
    }
}
