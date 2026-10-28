<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ThreatCheckController;

Route::post('/check-url', [ThreatCheckController::class, 'check']);
