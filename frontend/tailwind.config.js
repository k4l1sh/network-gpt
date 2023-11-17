/** @type {import('tailwindcss').Config} */
module.exports = {
  purge: ['./src/**/*.{js,jsx,ts,tsx}', './public/index.html'],
  darkMode: false,
  theme: {
    extend: {
      colors: {
        'terminal-green': '#32CD32',
      },
      fontFamily: {
        'terminal': ["'Courier New'", 'Courier', 'monospace'],
      }
    },
  },
  variants: {
    extend: {},
  },
  plugins: [],
};