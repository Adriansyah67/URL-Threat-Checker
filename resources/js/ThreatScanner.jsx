import React, { useState } from 'react';

export default function ThreatScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/check-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ url: url.trim() }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || (data.errors ? Object.values(data.errors).flat().join(', ') : 'Terjadi kesalahan saat memeriksa URL.'));
      }

      setResult(data.data);
    } catch (err) {
      setError(err.message || 'Gagal menghubungi server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-slate-800 border border-slate-700 shadow-2xl rounded-2xl p-8">
        
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-indigo-500/10 text-indigo-400 rounded-2xl mb-4 border border-indigo-500/20">
            <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">
            URL Threat Checker
          </h1>
          <p className="text-slate-400 mt-2 text-sm">
            Periksa keamanan tautan dari Malware, Phishing / Typosquatting, dan Penipuan Domain secara real-time via Google Safe Browsing & Heuristic Engine.
          </p>
        </div>

        {/* Form Input */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <input
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              className="w-full px-5 py-4 text-base bg-slate-950 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-4 px-6 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition duration-150 flex items-center justify-center shadow-lg shadow-indigo-600/30"
          >
            {loading ? (
              <span className="flex items-center space-x-2">
                <svg className="animate-spin h-5 w-5 text-white" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
                <span>Scanning...</span>
              </span>
            ) : (
              'Scan URL'
            )}
          </button>
        </form>

        {/* Error Notification */}
        {error && (
          <div className="mt-6 p-4 bg-red-950/60 border border-red-700 rounded-xl text-red-200 text-sm flex items-start space-x-3">
            <span className="text-red-400 font-bold text-base leading-none">⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {/* Scan Results */}
        {result && (
          <div className="mt-6">
            {result.is_safe ? (
              /* Safe Result */
              <div className="p-6 bg-emerald-950/40 border border-emerald-500/30 rounded-2xl">
                <div className="flex items-center space-x-3 mb-2">
                  <span className="p-2 bg-emerald-500/20 text-emerald-400 rounded-full">
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                  <div>
                    <h3 className="text-lg font-bold text-emerald-400">URL Aman</h3>
                    <p className="text-xs text-emerald-300/80">Tidak ditemukan indikasi bahaya atau catatan ancaman pada basis data keamanan.</p>
                  </div>
                </div>
                <div className="mt-3 text-xs text-slate-400 break-all bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-500 block mb-1">Target URL:</span>
                  {result.url}
                </div>
              </div>
            ) : (
              /* Threat Detected Result */
              <div className="p-6 bg-rose-950/40 border border-rose-500/40 rounded-2xl">
                <div className="flex items-center space-x-3 mb-2">
                  <span className="p-2 bg-rose-500/20 text-rose-400 rounded-full">
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  </span>
                  <div>
                    <h3 className="text-lg font-bold text-rose-400">Terindikasi Bahaya!</h3>
                    <p className="text-xs text-rose-300/80">URL ini terindikasi berbahaya dan berisiko bagi keamanan data Anda.</p>
                  </div>
                </div>

                <div className="mt-4 space-y-2.5">
                  <div className="flex items-center text-sm">
                    <span className="text-slate-400 w-32 shrink-0">Kategori Bahaya:</span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      {result.threat_type || 'Unknown Threat'}
                    </span>
                  </div>

                  {result.threat_detail && (
                    <div className="text-xs text-rose-200 bg-rose-950/70 p-3 rounded-lg border border-rose-800/60 leading-relaxed">
                      <span className="font-semibold block mb-0.5 text-rose-300">Detail Analisis:</span>
                      {result.threat_detail}
                    </div>
                  )}

                  <div className="text-xs text-slate-400 break-all bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block mb-1">Target URL:</span>
                    {result.url}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
}
