# MERN Authentication & Authorization Architecture

## Table of Contents

1. [Directory Structure](#directory-structure)
2. [Core Components](#core-components)
3. [Models](#models)
4. [Controllers](#controllers)
5. [Middleware](#middleware)
6. [Routes](#routes)
7. [Utilities](#utilities)
8. [Services](#services)
9. [Configuration](#configuration)
10. [Environment Variables](#environment-variables)

## Directory Structure

```
backend/
├── config/             # Configuration files
│   ├── db.js           # Database connection
│   └── default.js      # Environment variables
├── middleware/         # Custom middleware
│   ├── auth.js         # Authentication middleware
│   ├── validate.js     # Input validation
│   ├── rateLimiter.js  # API rate limiting
│   └── errorHandler.js # Global error handling
├── models/             # Mongoose models
│   ├── User.js         # User schema
│   ├── Role.js         # Role schema
│   ├── Permission.js   # Permission schema
│   └── Token.js        # Refresh token schema
├── controllers/        # Route controllers
│   ├── authController.js  # Auth functions
│   └── userController.js  # User management
├── routes/             # API routes
│   ├── authRoutes.js   # Auth endpoints
│   └── userRoutes.js   # User endpoints
├── utils/              # Utility functions
│   ├── jwt.js          # JWT helper functions
│   ├── validators.js   # Input validation rules
│   └── logger.js       # Logging utility
├── services/           # Business logic
│   ├── authService.js  # Auth business logic
│   └── emailService.js # Email notifications
├── app.js              # Express application
└── server.js           # Server entry point
```

## Core Components

### Application Entry Point (app.js)

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

## Models

### User Model (models/User.js)

```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false  // Don't return password by default
  },
  roles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lastLogin: Date,
  accountLocked: {
    type: Boolean,
    default: false
  },
  accountLockedUntil: Date,
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    select: false
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended'],
    default: 'active'
  }
}, {
  timestamps: true
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
```

### Role Model (models/Role.js)

```javascript
const mongoose = require('mongoose');

const RoleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  permissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }]
}, {
  timestamps: true
});

module.exports = mongoose.model('Role', RoleSchema);
```

### Permission Model (models/Permission.js)

```javascript
const mongoose = require('mongoose');

const PermissionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  resource: {
    type: String,
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: ['create', 'read', 'update', 'delete', 'manage']
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Permission', PermissionSchema);
```

### Token Model (models/Token.js)

```javascript
const mongoose = require('mongoose');

const TokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  token: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['refresh', 'resetPassword', 'emailVerification'],
    required: true
  },
  expires: {
    type: Date,
    required: true
  },
  blacklisted: {
    type: Boolean,
    default: false
  },
  userAgent: String,
  ipAddress: String
}, {
  timestamps: true
});

// Index for faster queries and automatic expiration
TokenSchema.index({ expires: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Token', TokenSchema);
```

## Controllers

### Authentication Controller (controllers/authController.js)

````javascript
const crypto = require('crypto');
const User = require('../models/User');
const Token = require('../models/Token');
const Role = require('../models/Role');
const ApiError = require('../utils/apiError');
const { signAccessToken, signRefreshToken, verifyToken, blacklistToken } = require('../utils/jwt');
const config = require('../config/default');
const emailService = require('../services/emailService');

// Register new user
exports.register = async (req, res, next) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new ApiError('Email already in use', 400));
    }

    // Get default user role
    const userRole = await Role.findOne({ name: 'user' });
    if (!userRole) {
      return next(new ApiError('Default role not found', 500));
    }

    // Create verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date();
    verificationExpires.setHours(verificationExpires.getHours() + 24);

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      roles: [userRole._id],
      verificationToken,
      verificationExpires
    });

    // Send verification email
    await emailService.sendVerificationEmail(
      user.email,
      user.firstName,
      verificationToken
    );

    // Generate tokens
    const accessToken = signAccessToken(user._id);
    const refreshToken = await signRefreshToken(
      user._id,
      req.headers['user-agent'],
      req.ip
    );

    res.status(201).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isEmailVerified: user.isEmailVerified
        },
        tokens: {
          accessToken,
          refreshToken
        }
      },
      message: 'Registration successful. Please verify your email.'
    });
  } catch (error) {
    next(error);
  }
};

// Login user
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return next(new ApiError('Invalid credentials', 401));
    }

    // Check if account is active
    if (user.status !== 'active') {
      return next(new ApiError('Account is not active', 401));
    }

    // Check if account is locked
    if (user.accountLocked && user.accountLockedUntil > Date.now()) {
      const remainingTime = Math.ceil((user.accountLockedUntil - Date.now()) / 1000 / 60);
      return next(new ApiError(`Account is locked. Try again in ${remainingTime} minutes`, 401));
    }

    // Check if password is correct
    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
      // Handle failed login attempts
      user.failedLoginAttempts += 1;

      // Lock account after 5 failed attempts
      if (user.failedLoginAttempts >= 5) {
        user.accountLocked = true;
        user.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      }

      await user.save();
      return next(new ApiError('Invalid credentials', 401));
    }

    // Reset failed login attempts
    user.failedLoginAttempts = 0;
    user.lastLogin = Date.now();
    if (user.accountLocked) {
      user.accountLocked = false;
      user.accountLockedUntil = undefined;
    }
    await user.save();

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      // Create a temporary token for 2FA verification
      const tempToken = crypto.randomBytes(20).toString('hex');

      // Save temp token to DB
      const tokenExpiry = new Date();
      tokenExpiry.setMinutes(tokenExpiry.getMinutes() + 10); // 10 minutes expiry

      await Token.create({
        userId: user._id,
        token: tempToken,
        type: 'twoFactor',
        expires: tokenExpiry
      });

      return res.status(200).json({
        status: 'success',
        message: '2FA verification required',
        data: {
          userId: user._id,
          require2FA: true,
          tempToken
        }
      });
    }

    // Generate tokens
    const accessToken = signAccessToken(user._id);
    const refreshToken = await signRefreshToken(
      user._id,
      req.headers['user-agent'],
      req.ip
    );

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isEmailVerified: user.isEmailVerified
        },
        tokens: {
          accessToken,
          refreshToken
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Verify 2FA
exports.verify2FA = async (req, res, next) => {
  try {
    const { userId, tempToken, code } = req.body;

    // Validate temp token
    const tokenRecord = await Token.findOne({
      userId,
      token: tempToken,
      type: 'twoFactor',
      blacklisted: false,
      expires: { $gt: Date.now() }
    });

    if (!tokenRecord) {
      return next(new ApiError('Invalid or expired token', 401));
    }

    // Get user
    const user = await User.findById(userId).select('+twoFactorSecret');
    if (!user) {
      return next(new ApiError('User not found', 404));
    }

    // Verify 2FA code
    const speakeasy = require('speakeasy');
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code
    });

    if (!verified) {
      return next(new ApiError('Invalid 2FA code', 401));
    }

    // Blacklist temp token
    tokenRecord.blacklisted = true;
    await tokenRecord.save();

    // Generate tokens
    const accessToken = signAccessToken(user._id);
    const refreshToken = await signRefreshToken(
      user._id,
      req.headers['user-agent'],
      req.ip
    );

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isEmailVerified: user.isEmailVerified
        },
        tokens: {
          accessToken,
          refreshToken
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Refresh access token
exports.refreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return next(new ApiError('Refresh token is required', 400));
    }

    // Check if token exists and is valid
    const tokenDoc = await Token.findOne({
      token: refreshToken,
      type: 'refresh',
      blacklisted: false,
      expires: { $gt: Date.now() }
    });

    if (!tokenDoc) {
      return next(new ApiError('Invalid or expired refresh token', 401));
    }

    // Verify token
    const decoded = await verifyToken(refreshToken, config.jwt.refreshTokenSecret);

    // Check if user exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new ApiError('User not found', 404));
    }

    // Generate new tokens
    const newAccessToken = signAccessToken(user._id);
    const newRefreshToken = await signRefreshToken(
      user._id,
      req.headers['user-agent'],
      req.ip
    );

    // Blacklist old refresh token
    await blacklistToken(refreshToken, user._id);

    res.status(200).json({
      status: 'success',
      data: {
        tokens: {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Logout
exports.logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    // Blacklist refresh token if provided
    if (refreshToken) {
      await blacklistToken(refreshToken, req.user._id);
    }

    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Verify email
exports.verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.params;

    const user = await User.findOne({
      verificationToken: token,
      verificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return next(new ApiError('Invalid or expired verification token', 400));
    }

    // Update user
    user.isEmailVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Email verified successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Request password reset
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json({
        status: 'success',
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date();
    resetExpires.setHours(resetExpires.getHours() + 1); // 1 hour expiry

    // Save to user
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetExpires;
    await user.save();

    // Send email
    await emailService.sendPasswordResetEmail(
      user.email,
      user.firstName,
      resetToken
    );

    res.status(200).json({
      status: 'success',
      message: 'If your email is registered, you will receive a password reset link'
    });
  } catch (error) {
    next(error);
  }
};

// Reset password
exports.resetPassword = async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return next(new ApiError('Invalid or expired reset token', 400));
    }

    // Update password
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // Blacklist all refresh tokens for this user
    await Token.updateMany(
      { userId: user._id, type: 'refresh' },
      { blacklisted: true }
    );

    res.status(200).json({
      status: 'success',
      message: 'Password reset successful'
    });
  } catch (error) {
    next(error);
  }
};

// Change password (authenticated user)
exports.changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password
    const user = await User.findById(req.user._id).select('+password');
    if (!user) {
      return next(new ApiError('User not found', 404));
    }

    // Check current password
    const isPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isPasswordCorrect) {
      return next(new ApiError('Current password is incorrect', 401));
    }

    // Update password
    user.password = newPassword;
    await user.save();

    // Blacklist all refresh tokens except current one
    if (req.body.refreshToken) {
      await Token.updateMany(
        {
          userId: user._id,
          type: 'refresh',
          token: { $ne: req.body.refreshToken }
        },
        { blacklisted: true }
      );
    }

    res.status(200).json({
      status: 'success',
      message: 'Password changed successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Setup 2FA
exports.setup2FA = async (req, res, next) => {
  try {
    const speakeasy = require('speakeasy');
    const QRCode = require('qrcode');

    // Generate new secret
    const secret = speakeasy.generateSecret({
      name: `MyApp:${req.user.email}`
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Save secret to user (temporarily)
    req.user.twoFactorSecret = secret.base32;
    await req.user.save();

    res.status(200).json({
      status: 'success',
      data: {
        secret: secret.base32,
        qrCode: qrCodeUrl
      },
      message: 'Scan the QR code with your authenticator app and confirm with the generated code'
    });
  } catch (error) {
    next(error);
  }
};

// Verify and enable 2FA
exports.verify2FASetup = async (req, res, next) => {
  try {
    const { code } = req.body;
    const speakeasy = require('speakeasy');

    // Get user with 2FA secret
    const user = await User.findById(req.user._id).select('+twoFactorSecret');

    // Verify code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code
    });

    if (!verified) {
      return next(new ApiError('Invalid verification code', 400));
    }

    // Enable 2FA
    user.twoFactorEnabled = true;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication enabled successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Disable 2FA
exports.disable2FA = async (req, res, next) => {
  try {
    const { password } = req.body;

    // Get user with password
    const user = await User.findById(req.user._id).select('+password');

    // Verify password
    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
      return next(new ApiError('Password is incorrect', 401));
    }

    // Disable 2FA
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication disabled successfully'
    });
  } catch (error) {
    next(error);
  }
};

## Middleware

### Authentication Middleware (middleware/auth.js)

```javascript
const { verifyToken } = require('../utils/jwt');
const Token = require('../models/Token');
const User = require('../models/User');
const Role = require('../models/Role');
const config = require('../config/default');
const ApiError = require('../utils/apiError');

// Protect routes
exports.protect = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(new ApiError('Not authenticated', 401));
    }

    const token = authHeader.split(' ')[1];

    // Verify token
    const decoded = await verifyToken(token, config.jwt.accessTokenSecret);

    // Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new ApiError('User no longer exists', 401));
    }

    // Check if user account is active
    if (user.status !== 'active') {
      return next(new ApiError('Account is not active', 401));
    }

    // Check if account is locked
    if (user.accountLocked && user.accountLockedUntil > Date.now()) {
      return next(new ApiError('Account is temporarily locked', 401));
    }

    // Set user in request
    req.user = user;
    next();
  } catch (error) {
    return next(new ApiError('Not authenticated', 401));
  }
};

// Authorization middleware
exports.authorize = (...requiredRoles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next(new ApiError('Not authenticated', 401));
      }

      // Get user with populated roles
      const user = await User.findById(req.user._id).populate({
        path: 'roles',
        populate: {
          path: 'permissions'
        }
      });

      // Extract user roles
      const userRoles = user.roles.map(role => role.name);

      // Check if user has required roles
      const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

      if (!hasRequiredRole) {
        return next(new ApiError('Not authorized to access this resource', 403));
      }

      next();
    } catch (error) {
      return next(new ApiError('Authorization failed', 403));
    }
  };
};

// Permission-based authorization
exports.hasPermission = (resource, action) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next(new ApiError('Not authenticated', 401));
      }

      // Get user with populated roles and permissions
      const user = await User.findById(req.user._id).populate({
        path: 'roles',
        populate: {
          path: 'permissions'
        }
      });

      // Check if user has admin role (full access)
      const isAdmin = user.roles.some(role => role.name === 'admin');
      if (isAdmin) return next();

      // Check for specific permission
      const hasPermission = user.roles.some(role =>
        role.permissions.some(
          perm => (perm.resource === resource &&
                  (perm.action === action || perm.action === 'manage'))
        )
      );

      if (!hasPermission) {
        return next(new ApiError(`Not authorized to ${action} ${resource}`, 403));
      }

      next();
    } catch (error) {
      return next(new ApiError('Permission check failed', 403));
    }
  };
};
````

### Input Validation Middleware (middleware/validate.js)

```javascript
const Joi = require('joi');
const ApiError = require('../utils/apiError');

module.exports = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const message = error.details.map(detail => detail.message).join(', ');
      return next(new ApiError(message, 400));
    }

    next();
  };
};
```

### Rate Limiter Middleware (middleware/rateLimiter.js)

```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

// Create Redis client
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD
});

// General rate limiter
exports.generalLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:general:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Auth rate limiter (stricter)
exports.authLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:auth:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: 'Too many authentication attempts, please try again after 15 minutes'
});

// Password reset limiter
exports.passwordResetLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:pwreset:'
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 requests per windowMs
  message: 'Too many password reset attempts, please try again after an hour'
});

// API limiter by user ID (after authentication)
exports.userRateLimiter = (requestsPerHour) => {
  return (req, res, next) => {
    if (!req.user) return next();

    const userId = req.user._id.toString();
    const key = `rl:user:${userId}`;

    redisClient.get(key, (err, count) => {
      if (err) return next(err);

      // Convert count to number or initialize to zero
      count = count ? parseInt(count) : 0;

      if (count >= requestsPerHour) {
        return res.status(429).json({
          status: 'error',
          message: `User rate limit exceeded. Maximum ${requestsPerHour} requests per hour allowed.`
        });
      }

      // Increment and set expiry
      redisClient.multi()
        .incr(key)
        .expire(key, 60 * 60) // 1 hour
        .exec((err) => {
          if (err) return next(err);
          next();
        });
    });
  };
};
```

### Error Handler Middleware (middleware/errorHandler.js)

```javascript
const config = require('../config/default');
const ApiError = require('../utils/apiError');

// Global error handler
module.exports = (err, req, res, next) => {
  console.error('Error:', err);

  let error = { ...err };
  error.message = err.message;
  error.stack = err.stack;

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    const message = `Duplicate field value: ${field}. Value '${value}' already exists`;
    error = new ApiError(message, 400);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(val => val.message);
    const message = `Invalid input data: ${errors.join(', ')}`;
    error = new ApiError(message, 400);
  }

  // Mongoose cast error
  if (err.name === 'CastError') {
    const message = `Invalid ${err.path}: ${err.value}`;
    error = new ApiError(message, 400);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = new ApiError('Invalid token. Please log in again', 401);
  }

  if (err.name === 'TokenExpiredError') {
    error = new ApiError('Token expired. Please log in again', 401);
  }

  // Send error response
  res.status(error.statusCode || 500).json({
    status: 'error',
    message: error.message || 'Internal server error',
    ...(config.env === 'development' && { stack: error.stack })
  });
};
```

## Routes

### Authentication Routes (routes/authRoutes.js)

```javascript
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect } = require('../middleware/auth');
const validate = require('../middleware/validate');
const authValidation = require('../utils/validators').auth;

// Public routes
router.post('/register', validate(authValidation.register), authController.register);
router.post('/login', validate(authValidation.login), authController.login);
router.post('/verify-2fa', validate(authValidation.verify2FA), authController.verify2FA);
router.post('/refresh-token', validate(authValidation.refreshToken), authController.refreshToken);
router.get('/verify-email/:token', authController.verifyEmail);
router.post('/forgot-password', validate(authValidation.forgotPassword), authController.forgotPassword);
router.post('/reset-password/:token', validate(authValidation.resetPassword), authController.resetPassword);

// Protected routes
router.use(protect);
router.post('/logout', authController.logout);
router.patch('/change-password', validate(authValidation.changePassword), authController.changePassword);
router.post('/setup-2fa', authController.setup2FA);
router.post('/verify-2fa-setup', validate(authValidation.verify2FASetup), authController.verify2FASetup);
router.post('/disable-2fa', validate(authValidation.disable2FA), authController.disable2FA);

module.exports = router;
```

### User Routes (routes/userRoutes.js)

```javascript
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { protect, authorize, hasPermission } = require('../middleware/auth');
const validate = require('../middleware/validate');
const userValidation = require('../utils/validators').user;

// Protected routes
router.use(protect);

// User routes
router.get('/me', userController.getMe);
router.patch('/update-profile', validate(userValidation.updateProfile), userController.updateProfile);
router.delete('/delete-account', userController.deleteAccount);

// Admin routes
router.use(authorize('admin'));
router.get('/', userController.getAllUsers);
router.get('/:id', userController.getUserById);
router.patch('/:id', userController.updateUser);

module.exports = router;
```

## Utilities

### JWT Utilities (utils/jwt.js)

```javascript
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');
const config = require('../config/default');
const Token = require('../models/Token');

// Sign access token
exports.signAccessToken = (userId) => {
  return jwt.sign({ id: userId }, config.jwt.accessTokenSecret, {
    expiresIn: config.jwt.accessTokenExpiry
  });
};

// Sign refresh token
exports.signRefreshToken = async (userId, userAgent, ipAddress) => {
  const refreshToken = jwt.sign(
    { id: userId },
    config.jwt.refreshTokenSecret,
    { expiresIn: config.jwt.refreshTokenExpiry }
  );

  // Save token to database
  const tokenExpiry = new Date();
  tokenExpiry.setSeconds(
    tokenExpiry.getSeconds() + parseInt(config.jwt.refreshTokenExpiry)
  );

  await Token.create({
    userId,
    token: refreshToken,
    type: 'refresh',
    expires: tokenExpiry,
    userAgent,
    ipAddress
  });

  return refreshToken;
};

// Verify token
exports.verifyToken = async (token, secret) => {
  const decoded = await promisify(jwt.verify)(token, secret);
  return decoded;
};

// Create Email Verification Token
exports.createEmailVerificationToken = async (userId, email) => {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date();
  expires.setHours(expires.getHours() + 24); // 24 hours expiry

  await Token.create({
    userId,
    token,
    type: 'emailVerification',
    expires
  });

  return token;
};

// Blacklist token
exports.blacklistToken = async (token, userId) => {
  await Token.findOneAndUpdate(
    { token, userId },
    { blacklisted: true }
  );
};
```

### API Error Utility (utils/apiError.js)

```javascript
class ApiError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = ApiError;
```

### Validation Schemas (utils/validators.js)

```javascript
const Joi = require('joi');

exports.auth = {
  register: Joi.object({
    firstName: Joi.string().trim().required(),
    lastName: Joi.string().trim().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required()
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$'))
      .message('Password must contain at least one uppercase letter, one lowercase letter, and one number')
  }),

  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),

  verify2FA: Joi.object({
    userId: Joi.string().required(),
    tempToken: Joi.string().required(),
    code: Joi.string().length(6).required()
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),

  forgotPassword: Joi.object({
    email: Joi.string().email().required()
  }),

  resetPassword: Joi.object({
    password: Joi.string().min(8).required()
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$'))
      .message('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required()
      .messages({ 'any.only': 'Passwords do not match' })
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(8).required()
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$'))
      .message('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required()
      .messages({ 'any.only': 'Passwords do not match' }),
    refreshToken: Joi.string()
  }),

  verify2FASetup: Joi.object({
    code: Joi.string().length(6).required()
  }),

  disable2FA: Joi.object({
    password: Joi.string().required()
  })
};

exports.user = {
  updateProfile: Joi.object({
    firstName: Joi.string().trim(),
    lastName: Joi.string().trim(),
    email: Joi.string().email()
  })
};
```

### Logging Utility (utils/logger.js)

```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

module.exports = logger;
```

## Services

### Auth Business Logic (services/authService.js)

```javascript
const userService = require('./userService');
const tokenService = require('./tokenService');
const emailService = require('./emailService');
const config = require('../config/default');

const register = async (req) => {
  // Implementation of register function
};

const login = async (req) => {
  // Implementation of login function
};

const forgotPassword = async (req) => {
  // Implementation of forgotPassword function
};

const resetPassword = async (req) => {
  // Implementation of resetPassword function
};

const verifyEmail = async (req) => {
  // Implementation of verifyEmail function
};

const resendVerificationEmail = async (req) => {
  // Implementation of resendVerificationEmail function
};

const logout = async (req) => {
  // Implementation of logout function
};

module.exports = { register, login, forgotPassword, resetPassword, verifyEmail, resendVerificationEmail, logout };
```

### Email Notifications (services/emailService.js)

```javascript
const nodemailer = require('nodemailer');
const config = require('../config/default');

// Create transporter
const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: config.email.port,
  secure: config.email.port === 465, // true for 465, false for other ports
  auth: {
    user: config.email.user,
    pass: config.email.pass
  }
});

// Send verification email
exports.sendVerificationEmail = async (email, name, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${token}`;

  const mailOptions = {
    from: `"My App" <${config.email.from}>`,
    to: email,
    subject: 'Email Verification',
    html: `
      <h1>Email Verification</h1>
      <p>Hello ${name},</p>
      <p>Thank you for registering with us. Please verify your email by clicking the link below:</p>
      <a href="${verificationUrl}">Verify Email</a>
      <p>This link will expire in 24 hours.</p>
      <p>If you did not create an account, please ignore this email.</p>
    `
  };

  await transporter.sendMail(mailOptions);
};

// Send password reset email
exports.sendPasswordResetEmail = async (email, name, token) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${token}`;

  const mailOptions = {
    from: `"My App" <${config.email.from}>`,
    to: email,
    subject: 'Password Reset',
    html: `
      <h1>Password Reset</h1>
      <p>Hello ${name},</p>
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <a href="${resetUrl}">Reset Password</a>
      <p>This link will expire in 1 hour.</p>
      <p>If you did not request a password reset, please ignore this email.</p>
    `
  };

  await transporter.sendMail(mailOptions);
};

// Send account locked notification
exports.sendAccountLockedEmail = async (email, name) => {
  const mailOptions = {
    from: `"My App" <${config.email.from}>`,
    to: email,
    subject: 'Account Temporarily Locked',
    html: `
      <h1>Account Temporarily Locked</h1>
      <p>Hello ${name},</p>
      <p>Your account has been temporarily locked due to multiple failed login attempts.</p>
      <p>You can try again after 15 minutes or reset your password using the "Forgot Password" option.</p>
      <p>If you did not attempt to log in, please reset your password immediately.</p>
    `
  };

  await transporter.sendMail(mailOptions);
};
```

## Configuration

### Default Configuration (config/default.js)

```javascript
require('dotenv').config();

module.exports = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 5000,
  mongodb: {
    uri: process.env.MONGODB_URI
  },
  jwt: {
    accessTokenSecret: process.env.JWT_ACCESS_SECRET,
    accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET,
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d'
  },
  email: {
    from: process.env.EMAIL_FROM,
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  cors: {
    origin: process.env.CORS_ORIGIN || '*'
  }
};
```

### Database Configuration (config/db.js)

```javascript
const mongoose = require('mongoose');
const config = require('./default');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(config.mongodb.uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
      useFindAndModify: false
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
```

## Environment Variables

```
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/auth-system
CORS_ORIGIN=http://localhost:3000
JWT_SECRET=secret
JWT_EXPIRES_IN=1h
EMAIL_USER=your_email_user
EMAIL_PASS=your_email_password
```

## Installation and Setup

1. Install dependencies:

```bash
npm install
```

2. Create `.env` file with required variables

3. Start the development server:

```bash
npm run dev
```

4. For production:

```bash
npm run build
npm start
```

## Dependencies

```json
{
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "compression": "^1.7.4",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "express-mongo-sanitize": "^2.2.0",
    "express-rate-limit": "^6.7.0",
    "helmet": "^7.0.0",
    "hpp": "^0.2.3",
    "joi": "^17.9.2",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.0.3",
    "morgan": "^1.10.0",
    "nodemailer": "^6.9.1",
    "qrcode": "^1.5.3",
    "rate-limit-redis": "^3.7.0",
    "redis": "^4.6.7",
    "speakeasy": "^2.0.0",
    "xss-clean": "^0.1.1"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}
```

## Security Features

1. **Password Security**

   - Bcrypt hashing
   - Minimum length and complexity requirements
   - Account locking after failed attempts

2. **Token Security**

   - JWT with short expiry for access tokens
   - Refresh token rotation
   - Token blacklisting

3. **Rate Limiting**

   - IP-based rate limiting
   - User-based rate limiting
   - Stricter limits for auth endpoints

4. **Input Validation**

   - Request body validation
   - Data sanitization
   - XSS protection

5. **Two-Factor Authentication**

   - TOTP-based 2FA
   - QR code generation
   - Backup codes

6. **Email Security**

   - Email verification
   - Password reset functionality
   - Account lock notifications

7. **CORS Protection**
   - Configurable origins
   - Secure cookie handling
   - Preflight request handling

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
- `PATCH /api/auth/change-password` - Change password
- `POST /api/auth/setup-2fa` - Setup 2FA
- `POST /api/auth/verify-2fa-setup` - Verify and enable 2FA
- `POST /api/auth/disable-2fa` - Disable 2FA

### User Management

- `GET /api/users/me` - Get current user profile
- `PATCH /api/users/update-profile` - Update user profile
- `DELETE /api/users/delete-account` - Delete user account

### Admin Routes

- `GET /api/users` - Get all users
- `GET /api/users/:id` - Get user by ID
- `PATCH /api/users/:id` - Update user

## Error Handling

The application includes a global error handling middleware that:

- Handles Mongoose validation errors
- Manages JWT authentication errors
- Processes duplicate key errors
- Provides detailed error messages in development
- Sanitizes error responses in production

## Best Practices

1. **Security**

   - Use environment variables for sensitive data
   - Implement proper input validation
   - Use secure password hashing
   - Implement rate limiting
   - Use HTTPS in production

2. **Performance**

   - Implement caching where appropriate
   - Use compression
   - Optimize database queries
   - Implement proper indexing

3. **Code Organization**

   - Follow MVC pattern
   - Use middleware for common functionality
   - Implement proper error handling
   - Use async/await for asynchronous operations

4. **Testing**
   - Write unit tests
   - Implement integration tests
   - Use test coverage tools
   - Implement CI/CD pipelines

## License

MIT
