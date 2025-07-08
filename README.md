# ShortURL Backend

Flask backend for the ShortURL application with comprehensive analytics and URL management.

## Features

- URL shortening with custom aliases
- Password protection for URLs
- Expiration control (5m, 1h, 1d, 7d, never)
- QR code generation
- Comprehensive analytics:
  - Click tracking
  - Geographic data (country, state, city)
  - Device, browser, and OS detection
  - IP address logging
  - Hourly and daily statistics
- Session-based user management
- CORS support for frontend integration

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
```

The server will start on `http://localhost:5000`

## API Endpoints

### URL Management
- `POST /api/shorten` - Create a shortened URL
- `GET /api/urls` - Get user's URLs
- `DELETE /api/urls/<id>` - Delete a URL
- `GET /api/analytics/<id>` - Get analytics for a URL

### URL Redirection
- `GET /<short_code>` - Redirect to original URL
- `POST /<short_code>` - Redirect with password (if protected)

### Utility
- `GET /api/health` - Health check
- `GET /static/qrcodes/<filename>` - Serve QR code images

## Data Storage

- URLs: `data/urls.json`
- Analytics: `data/analytics.json`
- QR Codes: `static/qrcodes/`

## Configuration

- Update `ADMIN_IPS` in `app.py` for admin access
- Change `app.secret_key` for production use
- Modify CORS settings as needed

## Analytics Features

The backend provides detailed analytics including:
- Total clicks and unique visitors
- Geographic distribution (countries, states, cities)
- Device types (Desktop, Mobile, Tablet)
- Browser usage (Chrome, Firefox, Safari, etc.)
- Operating systems (Windows, macOS, Linux, etc.)
- Traffic sources and referrers
- Hourly activity patterns
- Daily click history
- IP address details with location datapython app.py
