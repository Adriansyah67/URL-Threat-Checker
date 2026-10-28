import React from 'react';
import { createRoot } from 'react-dom/client';
import ThreatScanner from './ThreatScanner';

const rootElement = document.getElementById('root');
if (rootElement) {
    createRoot(rootElement).render(
        <React.StrictMode>
            <ThreatScanner />
        </React.StrictMode>
    );
}
