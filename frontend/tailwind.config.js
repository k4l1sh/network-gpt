/** @type {import('tailwindcss').Config} */
module.exports = {
  purge: ['./src/**/*.{js,jsx,ts,tsx}', './public/index.html'],
  darkMode: false, // or 'media' or 'class'
  theme: {
    extend: {
      colors: {
        'terminal-green': '#32CD32', // Use your exact limegreen color code
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