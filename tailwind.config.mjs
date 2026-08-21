/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Main Brand Palette
        ink: '#1B2A4A',
        gold: '#D9A441',
        maroon: '#7C2D3B',
        paper: '#FAF8F3',
        slate: '#4A4A45',

        // Semantic & Material System
        primary: {
          DEFAULT: '#D9A441',
          hover: '#7C2D3B',
          dark: '#7D5700',
          container: '#D9A441',
          'on-container': '#573C00',
        },
        secondary: {
          DEFAULT: '#7C2D3B',
          alt: '#984350',
          container: '#FE95A2',
          'on-container': '#782A38',
        },
        surface: {
          DEFAULT: '#FAF8F3',
          dim: '#EAE8E3',
          bright: '#FAF8F3',
          container: '#F0EEE9',
          'container-low': '#F5F3EE',
          'container-high': '#EAE8E3',
          'container-highest': '#E4E2DD',
        },
        'on-surface': {
          DEFAULT: '#1B2A4A',
          variant: '#4A4A45',
        },
        outline: {
          DEFAULT: '#817564',
          variant: '#D3C4B1',
        },
        // Dark theme tokens
        dark: {
          bg: '#0E1726',
          surface: '#121D30',
          card: '#16233B',
          rail: '#0B1320',
          border: 'rgba(211, 196, 177, 0.15)',
          text: '#FAF8F3',
          muted: '#C2BFB6',
        }
      },
      fontFamily: {
        tiro: ['"Tiro Bangla"', 'serif'],
        hind: ['"Hind Siliguri"', 'sans-serif'],
        heading: ['"Tiro Bangla"', 'serif'],
        body: ['"Hind Siliguri"', 'sans-serif'],
      },
      spacing: {
        'identity-rail-width': '280px',
        'content-max-width': '800px',
        'gutter': '2rem',
        'stack-sm': '1rem',
        'stack-md': '2.5rem',
        'stack-lg': '5rem',
      },
      borderRadius: {
        DEFAULT: '0.125rem',
        lg: '0.25rem',
        xl: '0.5rem',
        full: '9999px',
      },
      lineHeight: {
        bengali: '1.8',
        'bengali-loose': '2.0',
      }
    },
  },
  plugins: [],
};
