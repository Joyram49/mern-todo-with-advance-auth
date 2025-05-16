# MERN Todo App Backend

A robust backend system for a MERN stack Todo application with authentication, authorization, and advanced features.

## Directory Structure

```
backend/
├── config/                 # Configuration files
│   ├── db.js              # Database connection
│   └── default.js         # Environment variables
├── middleware/            # Custom middleware
│   ├── auth.js            # Authentication middleware
│   ├── validate.js        # Input validation
│   ├── rateLimiter.js     # API rate limiting
│   └── errorHandler.js    # Global error handling
├── models/                # Mongoose models
│   ├── user-model.js      # User schema
│   ├── todo-model.js      # Todo schema
│   ├── step-model.js      # Step schema
│   ├── archiveTodo-model.js # Archived todo schema
│   └── trashTodo-model.js # Trash todo schema
├── controllers/           # Route controllers
│   ├── authController.js  # Auth functions
│   └── userController.js  # User management
├── routes/                # API routes
│   ├── authRoutes.js      # Auth endpoints
│   └── userRoutes.js      # User endpoints
├── utils/                 # Utility functions
│   ├── jwt.js            # JWT helper functions
│   ├── validators.js      # Input validation rules
│   └── logger.js         # Logging utility
├── services/             # Business logic
│   ├── authService.js    # Auth business logic
│   └── emailService.js   # Email notifications
├── app.js                # Express application
└── server.js             # Server entry point
```

## Core Components

### 1. Application Entry Point (app.js)

```javascript
const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const rateLimit = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');
const config = require('./config/default');

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

// Create Express app
const app = express();

// Connect to MongoDB
mongoose.connect(config.mongodb.uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Security middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Enable CORS
app.use(cors({
  origin: config.cors.origin,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Add options for preflight requests
app.options('*', cors());

// Compression
app.use(compression());

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Rate limiting
app.use('/api/', rateLimit.generalLimiter);
app.use('/api/auth', rateLimit.authLimiter);
app.use('/api/auth/forgot-password', rateLimit.passwordResetLimiter);

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// 404 handler
app.all('*', (req, res, next) => {
  res.status(404).json({
    status: 'error',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Global error handler
app.use(errorHandler);

module.exports = app;
```

### 2. User Model (models/user-model.js)

```javascript
import mongoose from "mongoose";

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      loweCase: true,
    },
    password: {
      type: String,
      required: true,
    },
    profile_picture: String,
    refreshTokens: [
      {
        type: String,
      },
    ],
  },
  {
    timestamps: true,
  }
);

export const User = mongoose.models.User ?? mongoose.model("User", UserSchema);
```

### 3. Todo Model (models/todo-model.js)

```javascript
import mongoose from "mongoose";

const TodoSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    notes: {
      type: String,
      trim: true,
    },
    isFavourite: {
      type: Boolean,
      default: false,
    },
    scheduleDate: { type: Date },
    dueDate: {
      type: Date,
      default: null,
    },
    reminder: {
      type: Date,
      default: null,
    },
    reminderSentAt: { type: Date },
    status: {
      type: String,
      enum: ["outdated", "inProgress", "completed"],
      default: "inProgress",
    },
    steps: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Step",
      },
    ],
    deletedAt: { type: Date },
    archivedAt: { type: Date },
  },
  { timestamps: true }
);

export const Todo = mongoose.models.Todo ?? mongoose.model("Todo", TodoSchema);
```

### 4. Step Model (models/step-model.js)

```javascript
import mongoose, { Schema } from "mongoose";

const StepSchema = new mongoose.Schema(
  {
    todo: { type: Schema.Types.ObjectId, ref: "Todo", required: true },
    title: { type: String, required: true, trim: true },
    isCompleted: { type: Boolean, default: false },
    order: {
      type: Number,
      default: 0,
      required: true,
    },
  },
  { timestamps: true }
);

export const Step = mongoose.models.Step ?? mongoose.model("Step", StepSchema);
```

### 5. Archived Todo Model (models/archiveTodo-model.js)

```javascript
import mongoose, { Schema } from "mongoose";

const ArchivedTodoSchema = new mongoose.Schema(
  {
    originalTodoId: {
      type: Schema.Types.ObjectId,
      ref: "Todo",
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    title: { type: String, required: true },
    notes: { type: String },
    isImportant: { type: Boolean, default: false },
    scheduleDate: { type: Date },
    dueDate: { type: Date },
    reminder: { type: Boolean, default: false },
    status: {
      type: String,
      enum: ["active", "completed", "not completed"],
      default: "active",
    },
    archivedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export const ArchivedTodo =
  mongoose.models.ArchivedTodo ??
  mongoose.model("ArchivedTodo", ArchivedTodoSchema);
```

### 6. Trash Todo Model (models/trashTodo-model.js)

```javascript
import mongoose, { Schema } from "mongoose";

const trashTodoSchema = new mongoose.Schema(
  {
    originalTodoId: {
      type: Schema.Types.ObjectId,
      ref: "Todo",
      required: true,
    },
    user: { type: Schema.Types.ObjectId, ref: "User", required: true },
    title: { type: String, required: true },
    notes: { type: String },
    isImportant: { type: Boolean, default: false },
    scheduleDate: { type: Date },
    dueDate: { type: Date },
    reminder: { type: Boolean, default: false },
    status: {
      type: String,
      enum: ["active", "completed", "not completed"],
      default: "active",
    },
    steps: [{ type: Schema.Types.ObjectId, ref: "Step" }],
    deletedAt: { type: Date, default: Date.now, index: { expires: "7d" } },
  },
  { timestamps: true }
);

export const TrashTodo =
  mongoose.models.TrashTodo ?? mongoose.model("TrashTodo", trashTodoSchema);
```

## Features

- 🔐 **Authentication & Authorization**

  - JWT-based authentication
  - Role-based access control
  - Two-factor authentication (2FA)
  - Password reset functionality
  - Email verification

- 🛡️ **Security**

  - Rate limiting
  - Input validation
  - XSS protection
  - CORS configuration
  - Password hashing
  - Account locking

- 📧 **Email Services**

  - Email verification
  - Password reset
  - Account notifications

- 📝 **Todo Management**
  - Create, read, update, delete todos
  - Todo archiving
  - Todo trash system
  - Step management
  - Due dates and reminders

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/verify-2fa` - Verify 2FA code
- `POST /api/auth/refresh-token` - Refresh access token
- `GET /api/auth/verify-email/:token` - Verify email
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password/:token` - Reset password
- `POST /api/auth/logout` - User logout

### User Management

- `GET /api/users/me` - Get current user profile
- `PATCH /api/users/update-profile` - Update user profile
- `DELETE /api/users/delete-account` - Delete user account

### Admin Routes

- `GET /api/users` - Get all users
- `GET /api/users/:id` - Get user by ID
- `PATCH /api/users/:id` - Update user

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
NODE_ENV=development
PORT=5000

# MongoDB Connection
MONGODB_URI=mongodb://localhost:27017/todo-app

# JWT Settings
JWT_ACCESS_SECRET=your_access_token_secret_key_here
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_SECRET=your_refresh_token_secret_key_here
JWT_REFRESH_EXPIRY=7d

# Email Configuration
EMAIL_FROM=noreply@yourapp.com
EMAIL_HOST=smtp.mailtrap.io
EMAIL_PORT=2525
EMAIL_USER=your_email_user
EMAIL_PASS=your_email_password

# Frontend URL
FRONTEND_URL=http://localhost:3000

# CORS
CORS_ORIGIN=http://localhost:3000

# Redis (for rate limiting)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
```

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create `.env` file with required variables
4. Start the server:
   ```bash
   npm start
   ```

## Dependencies

- Express.js - Web framework
- Mongoose - MongoDB ODM
- JWT - Authentication
- Bcrypt - Password hashing
- Nodemailer - Email service
- Redis - Rate limiting
- Joi - Input validation
- Helmet - Security headers
- CORS - Cross-origin resource sharing

## Development

For development with hot-reload:

```bash
npm run dev
```

## Production

For production build:

```bash
npm run build
```

## Error Handling

The application includes a global error handling middleware that:

- Handles Mongoose validation errors
- Manages JWT authentication errors
- Processes duplicate key errors
- Provides detailed error messages in development
- Sanitizes error responses in production

## Security Features

- Rate limiting for API endpoints
- Input validation and sanitization
- XSS protection
- CORS configuration
- Secure password hashing
- Account locking after failed attempts
- JWT token management
- Two-factor authentication

## License

MIT
