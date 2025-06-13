# KUP Authentication Client

A React-based frontend application for KUP (Keycloak User Portal) authentication.

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher) or yarn

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```

### Available Scripts

In the project directory, you can run:

- `npm start` or `yarn start` - Runs the app in development mode. Open [http://localhost:3000](http://localhost:3000) to view it in your browser.
- `npm test` or `yarn test` - Launches the test runner.
- `npm run build` or `yarn build` - Builds the app for production to the `build` folder.

### Environment Variables

The following environment variables can be configured in a `.env` file:

```
REACT_APP_KUP_AUTH_URL=http://localhost:3001/login
REACT_APP_CLIENT_ID=myclient
REACT_APP_REDIRECT_URI=http://localhost:3000/profile
```

## Project Structure

- `/src` - Source code
  - `/pages` - Page components
  - `/components` - Reusable UI components
  - `/utils` - Utility functions
  - `App.jsx` - Main application component
  - `index.js` - Application entry point
- `/public` - Static files

## Features

- Login with KUP authentication
- User profile display
- Secure token handling
- Responsive design

## License

This project is licensed under the MIT License.
