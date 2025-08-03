import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';

// https://vite.dev/config/
// Vite natively supports SVG imports with the ?url suffix:
// import logoUrl from './logo.svg?url';
// This allows you to use SVGs as URLs in <img src={logoUrl} />.
// No extra configuration is needed for this feature.
// If you see type errors for 'path' or 'url', run: npm install --save-dev @types/node
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@frontend': resolve(__dirname, 'src'),
    },
  },
});
