# SQLi Scanner - Chrome Extension

Production-grade Chrome Extension for detecting SQL injection vulnerabilities.

## Prerequisites

- Node.js (v16 or higher)
- npm (comes with Node.js)
- Google Chrome browser

## Installation

1. Clone this repository:
git clone https://github.com/YOUR-USERNAME/sqli-scanner-extension.git
cd sqli-scanner-extension

text

2. Install dependencies:
npm install

text

3. Build the extension:
npm run build

text

4. Load in Chrome:
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `dist/` folder

## Usage

1. Open Chrome DevTools (F12)
2. Navigate to "SQLi Scanner" tab
3. Click "Start Scan" to test current page
4. Export results as JSON
