# Hack ID by [hack.sv](https://hack.sv)

A comprehensive identity management system for [hack.sv](https://hack.sv) events, built with Flask.

## 🚀 Features

### Core Authentication

-   **Google OAuth 2.0** - Secure authentication with Google accounts
-   **User Registration** - Complete profile setup with legal name, preferred name, pronouns, and date of birth
-   **Session Management** - Secure session handling with CSRF protection

### User Management

-   **Profile Dashboard** - Personalized user dashboard with profile information
-   **Event Enrollment** - Track user participation across multiple events
-   **Discord Integration** - Link Discord accounts and manage server roles
-   **Pronoun Support** - Inclusive pronoun system (he/him/his, she/her/hers, they/them/theirs, other)

### Admin Features

-   **Admin Panel** - Comprehensive user management interface
-   **API Key System** - Secure API access with Bearer token authentication
-   **Data Import/Export** - CSV and JSON data processing capabilities
-   **User Analytics** - Event participation tracking and statistics

### Privacy & Compliance

-   **GDPR Compliant** - Full data deletion and privacy controls
-   **Opt-out System** - Permanent data deletion with secure token system
-   **Privacy Policy** - Comprehensive privacy documentation
-   **Data Minimization** - Collect only necessary information
-   **Automatic Cleanup** - Temporary event data auto-deletion

### Security Features

-   **CSRF Protection** - All forms protected against CSRF attacks
-   **Session Security** - Secure session cookies with httpOnly flag
-   **Input Validation** - All user inputs validated and sanitized
-   **SQL Injection Prevention** - Parameterized queries throughout
-   **Rate Limiting** - API endpoints protected against abuse (disabled in development)
-   **Privacy by Design** - Minimal data collection and automatic cleanup

## 🛠️ Quick Start

### Prerequisites

-   Python 3.8+
-   Google Cloud Platform account
-   Discord Bot (optional, for Discord integration)
-   AWS SES account (optional, for email notifications)

### 1. Clone and Install

```bash
git clone https://github.com/your-org/hack-id.git
cd hack-id
pip install -r requirements.txt
```

### 2. Environment Setup

Copy the example environment file and configure your settings:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Required - Flask Configuration
SECRET_KEY=your-super-secret-key-here
PROD=FALSE

# Required - Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Optional - Discord Integration
DISCORD_BOT_TOKEN=your-discord-bot-token
DISCORD_GUILD_ID=your-discord-server-id

# Optional - Email Notifications
MAIL_HOST=email-smtp.us-west-1.amazonaws.com
MAIL_PORT=587
MAIL_USERNAME=your-aws-ses-smtp-username
MAIL_PASSWORD=your-aws-ses-smtp-password
```

### 3. Google OAuth Setup

1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable the **Google+ API** and **People API**
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs:
    - Development: `http://127.0.0.1:3000/auth/google/callback`
    - Production: `https://yourdomain.com/auth/google/callback`

### 4. Database Initialization

The database will be automatically created on first run:

```bash
python app.py
```

### 5. Admin Setup

Configure your admin email in `models/admin.py` or use the admin panel to manage permissions.

## 📁 Project Structure

```
hack-id/
├── app.py                      # Main Flask application
├── config.py                   # Configuration management
├── requirements.txt            # Python dependencies
├── .env.example               # Environment template
├── PRIVACY.md                 # Privacy policy
├── generate_opt_out_links.py  # Privacy compliance script
│
├── models/                    # Data models
│   ├── user.py               # User management
│   ├── admin.py              # Admin permissions
│   └── opt_out.py            # Privacy opt-out system
│
├── routes/                    # Flask routes
│   ├── auth.py               # Authentication & registration
│   ├── admin.py              # Admin panel
│   └── opt_out.py            # Privacy management
│
├── services/                  # Business logic
│   ├── auth_service.py       # Authentication services
│   ├── dashboard_service.py  # Dashboard data
│   └── data_deletion.py      # Privacy compliance
│
├── utils/                     # Utilities
│   ├── database.py           # Database connection
│   ├── db_init.py            # Database initialization
│   ├── discord.py            # Discord API integration
│   ├── events.py             # Event management
│   └── error_handling.py     # Error handling
│
├── templates/                 # HTML templates
│   ├── auth.html             # Login/registration
│   ├── dashboard.html        # User dashboard
│   ├── register.html         # User registration
│   ├── admin/                # Admin templates
│   └── opt_out.html          # Privacy pages
│
└── static/                    # Static files
    ├── events.json           # Event definitions
    └── permissions.json      # API permissions
```


## ✅ Testing

Run the full automated suite (unit + route + Playwright API interaction tests):

```bash
python -m pytest -q
```

Run the auth/OAuth interaction coverage gate at 100%:

```bash
coverage run --include="tests/test_auth_routes.py,tests/test_oauth_routes.py" -m pytest -q tests/test_auth_routes.py tests/test_oauth_routes.py
coverage report -m --fail-under=100
```

> Note: Playwright is included for interaction tests via API request contexts (no local browser binary required for these tests).

## 🔧 Configuration

### Environment Variables

| Variable               | Required | Description                       |
| ---------------------- | -------- | --------------------------------- |
| `SECRET_KEY`           | Yes      | Flask secret key for sessions     |
| `PROD`                 | No       | Set to `TRUE` for production mode |
| `GOOGLE_CLIENT_ID`     | Yes      | Google OAuth client ID            |
| `GOOGLE_CLIENT_SECRET` | Yes      | Google OAuth client secret        |
| `DISCORD_BOT_TOKEN`    | No       | Discord bot token for integration |
| `DISCORD_GUILD_ID`     | No       | Discord server ID                 |
| `MAIL_HOST`            | No       | AWS SES SMTP host                 |
| `MAIL_PORT`            | No       | AWS SES SMTP port (587)           |
| `MAIL_USERNAME`        | No       | AWS SES SMTP username             |
| `MAIL_PASSWORD`        | No       | AWS SES SMTP password             |

### Production Deployment

For production deployment:

1. Set `PROD=TRUE` in your environment
2. Use HTTPS for all URLs
3. Configure proper database backups
4. Set up monitoring and logging
5. Review security settings in `config.py`

## 🚀 Deployment

### Deploying to Coolify

[Coolify](https://coolify.io/) is a self-hosted platform-as-a-service that makes deployment easy. This project includes Docker configuration for seamless Coolify deployment.

#### Prerequisites

- A Coolify instance (self-hosted or managed)
- A GitHub/GitLab repository with this code
- Domain name (optional, but recommended for production)

#### Deployment Steps

1. **Create a New Resource in Coolify**
   - Log into your Coolify dashboard
   - Click "New Resource" → "Application"
   - Select your Git repository

2. **Configure Build Settings**
   - **Build Pack**: Select "Dockerfile" (recommended) or "Nixpacks"
   - **Dockerfile Path**: `Dockerfile` (default)
   - **Port**: `3000`

3. **Set Environment Variables**

   In Coolify's environment variables section, add the following:

   ```env
   # Required - Flask Configuration
   SECRET_KEY=your-super-secret-key-here
   PROD=TRUE

   # Required - Google OAuth
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   REDIRECT_URI=https://yourdomain.com/auth/google/callback

   # Optional - Discord Integration
   DISCORD_BOT_TOKEN=your-discord-bot-token
   DISCORD_GUILD_ID=your-discord-server-id

   # Optional - Email Notifications (AWS SES)
   MAIL_HOST=email-smtp.us-west-1.amazonaws.com
   MAIL_PORT=587
   MAIL_USERNAME=your-aws-ses-smtp-username
   MAIL_PASSWORD=your-aws-ses-smtp-password
   EMAIL_SENDER=your-email@domain.com
   EMAIL_SENDER_NAME=Your Name

   # Optional - PostHog Analytics
   POSTHOG_API_KEY=your-posthog-api-key
   POSTHOG_HOST=https://us.i.posthog.com
   POSTHOG_ENABLED=true

   # Optional - Listmonk Integration
   LISTMONK_URL=https://mail.yourdomain.com
   LISTMONK_API_KEY=your-listmonk-api-key
   LISTMONK_ENABLED=true
   ```

4. **Configure Persistent Storage**

   Add a persistent volume for the SQLite database:
   - **Source Path**: `/app/users.db`
   - **Destination Path**: `/data/users.db`
   - This ensures your database persists across deployments

   **Note**: The database and all tables will be automatically created on first startup. If you have an existing database, see the "Uploading an Existing Database" section below.

5. **Set Up Health Checks**

   Coolify will automatically use the health check defined in the Dockerfile:
   - **Health Check URL**: `/health`
   - **Interval**: 30 seconds

6. **Deploy**
   - Click "Deploy" to start the deployment
   - Coolify will build the Docker image and start the container
   - Monitor the build logs for any errors

7. **Configure Domain (Optional)**
   - In Coolify, go to "Domains" section
   - Add your custom domain
   - Coolify will automatically handle SSL certificates via Let's Encrypt

#### Deploying Discord Bot (Optional)

If you want to run the Discord bot alongside the web app:

1. **Option 1: Separate Service in Coolify**
   - Create a new application in Coolify
   - Use the same repository
   - Set **Start Command**: `python discord_bot.py`
   - Add the same environment variables (especially `DISCORD_BOT_TOKEN` and `DISCORD_GUILD_ID`)
   - Mount the same database volume to share data with the web app

2. **Option 2: Docker Compose (Advanced)**
   - Use the included `docker-compose.yml` file
   - In Coolify, select "Docker Compose" as the build pack
   - This will run both the web app and Discord bot in the same deployment

### Docker Deployment (Other Platforms)

For deploying to other platforms (Railway, Render, Fly.io, etc.):

#### Using Dockerfile

```bash
# Build the image
docker build -t hack-id .

# Run the container
docker run -d \
  -p 3000:3000 \
  -e SECRET_KEY=your-secret-key \
  -e PROD=TRUE \
  -e GOOGLE_CLIENT_ID=your-client-id \
  -e GOOGLE_CLIENT_SECRET=your-client-secret \
  -v $(pwd)/data:/app/data \
  hack-id
```

#### Using Docker Compose

```bash
# Create a .env file with your environment variables
cp .env.example .env
# Edit .env with your values

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Database Persistence

**Important**: The SQLite database (`users.db`) must be persisted across deployments:

- **Coolify**: Use persistent volumes (configured in step 4 above)
- **Docker**: Mount a volume to `/app/users.db` or `/app/data`
- **Docker Compose**: The included `docker-compose.yml` already configures this

#### Uploading an Existing Database to Coolify

If you have an existing `users.db` file with configured users and admins, you can upload it to Coolify:

**Method 1: Using Coolify's File Manager (Easiest)**

1. In Coolify, go to your application
2. Navigate to "Storages" or "Volumes" section
3. Find the persistent volume for the database
4. Use the file manager to upload your `users.db` file
5. Restart the application

**Method 2: Using SSH/SCP**

1. Find your Coolify server's SSH details
2. Locate the volume path (usually something like `/var/lib/docker/volumes/...`)
3. Upload the database file:
   ```bash
   # From your local machine
   scp users.db user@your-server:/path/to/volume/users.db
   ```
4. Restart the application in Coolify

**Method 3: Using Docker Commands on Server**

1. SSH into your Coolify server
2. Find your container:
   ```bash
   docker ps | grep hack-id
   ```
3. Copy the database into the container:
   ```bash
   docker cp users.db <container-id>:/app/users.db
   ```
4. Restart the container in Coolify

**Important Notes:**
- Make sure to backup your existing database before uploading
- The database file should have proper permissions (readable by the container)
- After uploading, verify the database is working by checking the health endpoint
- The application will automatically create tables if they don't exist, but won't overwrite existing data

### Post-Deployment Checklist

After deploying:

- [ ] Verify the health check endpoint: `https://yourdomain.com/health`
- [ ] Test Google OAuth login flow
- [ ] Set up your first admin user (see Admin Setup section)
- [ ] Configure database backups
- [ ] Test Discord integration (if enabled)
- [ ] Review application logs for any errors
- [ ] Set up monitoring and alerts

## 🔐 Security Features

-   **CSRF Protection** - All forms protected against CSRF attacks
-   **Session Security** - Secure session cookies with httpOnly flag
-   **Input Validation** - All user inputs validated and sanitized
-   **SQL Injection Prevention** - Parameterized queries throughout
-   **Rate Limiting** - API endpoints protected against abuse (disabled in development)
-   **Privacy by Design** - Minimal data collection and automatic cleanup

## 📊 API Documentation

The system includes a RESTful API with Bearer token authentication:

### Authentication

```bash
curl -H "Authorization: Bearer your-api-key" \
     https://yourdomain.com/api/users
```

### Available Endpoints

-   `GET /api/users` - List users (admin only)
-   `GET /api/events` - List events
-   `POST /api/users/{id}/events` - Enroll user in event
-   `DELETE /api/users/{id}` - Delete user (privacy compliance)

## 🔒 Privacy Compliance

This system is designed with privacy-first principles:

### GDPR Compliance

-   **Right to Access** - Users can view all their data
-   **Right to Rectification** - Users can update their information
-   **Right to Erasure** - Complete data deletion system
-   **Right to Portability** - Data export functionality
-   **Data Minimization** - Only collect necessary information

### Privacy Tools

-   **Opt-out Links** - Generate permanent deletion links for email campaigns
-   **Automatic Cleanup** - Temporary event data deleted after events
-   **Privacy Dashboard** - Users control their data

### Generate Privacy Links

```bash
python generate_opt_out_links.py --output privacy_links.csv
```

## 🤖 Discord Integration

### Bot Setup

1. Create a Discord application at [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a bot and copy the token
3. Invite bot to your server with appropriate permissions
4. Configure `DISCORD_BOT_TOKEN` and `DISCORD_GUILD_ID`

### Features

-   Automatic role assignment for verified users
-   Discord username display on dashboard
-   Role removal during data deletion

## 🧪 Development

### Development Mode Features

When `DEBUG_MODE=True` (default when `PROD=FALSE`):

-   **Rate limiting disabled** - No API or endpoint rate limits
-   **Detailed error messages** - Full stack traces and debug info
-   **Auto-reload** - Server restarts on code changes
-   **Debug logging** - Verbose console output

### Running Tests

```bash
python -m pytest tests/
```

### Database Management

```bash
# Initialize database
python utils/db_init.py

# Import user data
python import_users.py

# Generate privacy links
python generate_opt_out_links.py
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

-   Create an issue on GitHub
-   Check the [Privacy Policy](PRIVACY.md) for data handling information
-   Review the configuration documentation above

## 🙏 Acknowledgments

-   Built with Flask and modern web security practices
-   Designed for hackathon organizers and event management
-   Privacy-first approach inspired by GDPR and modern data protection standards
