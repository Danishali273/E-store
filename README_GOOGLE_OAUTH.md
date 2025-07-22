# Setting up Google OAuth for E-Store

Follow these steps to enable Google Sign-In for your E-Store application:

1. Go to the Google Cloud Console (https://console.cloud.google.com/)

2. Create a new project or select an existing one

3. Enable the Google+ API and Google OAuth2 API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API" and "Google OAuth2 API"
   - Enable both APIs

4. Configure the OAuth consent screen:
   - Go to "APIs & Services" > "OAuth consent screen"
   - Choose "External" user type
   - Fill in the required information:
     - App name: "E-Store"
     - User support email: Your email
     - Developer contact information: Your email

5. Create OAuth 2.0 Client ID:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth Client ID"
   - Choose "Web application"
   - Add authorized redirect URIs:
     - For local development: `http://localhost:5000/login/google/callback`
     - For production: `https://your-domain.com/login/google/callback`

6. Note down your Client ID and Client Secret

7. Update your .env file with the following variables:
   ```
   GOOGLE_CLIENT_ID=your_client_id_here
   GOOGLE_CLIENT_SECRET=your_client_secret_here
   ```

8. Restart your Flask application

Now users can sign in with their Google accounts, and their email will be automatically verified!
