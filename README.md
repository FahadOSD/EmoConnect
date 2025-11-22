# EmoConnect 

A comprehensive emotional wellness and task management platform built with Django REST Framework and React Native.

## 🚀 Features

- **User Management**: Email-based authentication with JWT tokens
- **Social Authentication**: Google and Apple OAuth integration
- **Task Management**: Create, organize, and track personal tasks with notifications
- **Call Management**: Schedule and manage emotional support calls
- **Email Verification**: Secure OTP-based email verification system
- **API Documentation**: Interactive Swagger/OpenAPI documentation

## 🛠️ Tech Stack

### Backend
- **Django 5.2.7** - Web framework
- **Django REST Framework** - API development
- **SimpleJWT** - JWT authentication
- **django-allauth** - Social authentication
- **dj-rest-auth** - Authentication endpoints
- **drf-yasg** - API documentation
- **Celery** - Task queue for notifications
- **SQLite** - Database (development)

### Frontend
- **React Native** - Mobile application
- **Expo** - Development platform

## 📁 Project Structure

```
EmoConnect/
├── apps/
│   ├── users/           # User management and authentication
│   ├── task_management/ # Task CRUD and notifications
│   └── call_management/ # Call scheduling and management
├── core/               # Django settings and configuration
├── static/            # Static files
└── manage.py          # Django management script
```

## ⚙️ Installation

### Prerequisites
- Python 3.12+
- Node.js 18+
- Git

### Backend Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd EmoConnect
```

2. **Create virtual environment**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Environment Configuration**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Database Setup**
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

6. **Run Development Server**
```bash
python manage.py runserver 8001
```

### Frontend Setup (React Native)

1. **Navigate to mobile directory**
```bash
cd mobile/  # or wherever your RN app is located
```

2. **Install dependencies**
```bash
npm install
# or
yarn install
```

3. **Start Expo development server**
```bash
npx expo start
```

## 📚 API Documentation

Once the server is running, access the interactive API documentation at:
- **Swagger UI**: http://localhost:8001/api/docs/
- **ReDoc**: http://localhost:8001/api/redoc/

## 🔐 Authentication

### JWT Authentication
The API uses JWT tokens for authentication. Include the token in the Authorization header:

```bash
Authorization: Bearer <your-access-token>
```

### Email Registration Flow
1. **Register**: POST `/users/register/` - Send email for OTP
2. **Verify**: POST `/users/` - Verify OTP and create account
3. **Login**: POST `/auth/login/` - Get JWT tokens

### Social Authentication
- **Google**: GET `/auth/google/` - Initiate Google OAuth
- **Apple**: GET `/auth/apple/` - Initiate Apple OAuth

## 📝 API Endpoints

### Users
- `POST /users/register/` - Register new user (sends OTP)
- `POST /users/` - Create user (verify OTP)
- `GET /users/` - Get current user profile
- `PUT /users/{id}/` - Update user profile

### Tasks
- `GET /task/tasks/` - List user's tasks
- `POST /task/tasks/` - Create new task
- `PUT /task/tasks/{id}/` - Update task
- `DELETE /task/tasks/{id}/` - Delete task

### Calls
- `GET /call/calls/` - List user's calls
- `POST /call/calls/` - Schedule new call
- `PUT /call/calls/{id}/` - Update call
- `DELETE /call/calls/{id}/` - Cancel call

## 🔧 Development

### Running Tests
```bash
python manage.py test
```

### Code Quality
```bash
# Format code
black .
isort .

# Lint code
flake8 .
```

### Database Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Create Superuser
```bash
python manage.py createsuperuser
```

## 🚀 Deployment

### Environment Variables
Required environment variables:
- `DEBUG` - Set to False in production
- `SECRET_KEY` - Django secret key
- `DATABASE_URL` - Database connection string
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth secret
- `APPLE_CLIENT_ID` - Apple OAuth client ID
- `EMAIL_HOST_USER` - SMTP email username
- `EMAIL_HOST_PASSWORD` - SMTP email password

### Production Setup
1. Set `DEBUG=False` in settings
2. Configure production database (PostgreSQL recommended)
3. Set up Redis for Celery
4. Configure web server (Nginx + Gunicorn)
5. Set up SSL certificates

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For support, email support@emoconnect.com or join our community Discord.

## 🙏 Acknowledgments

- Django REST Framework team
- React Native community
- All contributors and testers

---

**EmoConnect** - Connecting emotions, managing life. 💙