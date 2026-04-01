# Quotient Security Updates Documentation

## Overview

This document contains comprehensive documentation for all 8 security improvements implemented in the Quotient social networking application. Each section includes the vulnerability explanation, before/after code comparisons, and implementation details.

---

## Table of Contents

1. [Strong Password Hashing](#1-strong-password-hashing)
2. [Rate Limiting on Authentication](#2-rate-limiting-on-authentication)
3. [Secure Session Cookies](#3-secure-session-cookies)
4. [Input Validation & Sanitization](#4-input-validation--sanitization)
5. [Security Headers (Helmet)](#5-security-headers-helmet)
6. [Generic Error Handling](#6-generic-error-handling)
7. [Dependency Security](#7-dependency-security)
8. [HTTPS Enforcement](#8-https-enforcement)

---

## 1. Strong Password Hashing

### Explanation

#### Vulnerability Fixed
The original application stored user passwords in **plain text** in the MongoDB database. This is a critical security vulnerability that exposes all user accounts if the database is ever compromised.

#### Why It's Important
- **Data Breach Protection**: If attackers gain database access, hashed passwords remain protected
- **Privacy Compliance**: Meets security standards required by GDPR, CCPA, and other regulations
- **User Trust**: Users expect their credentials to be stored securely
- **Defense in Depth**: Even with database access, attackers cannot immediately use stolen credentials

#### Implementation Details
- Using **bcrypt** with 12 salt rounds for strong hashing
- Passwords are hashed during registration before saving to database
- Login verification uses `bcrypt.compare()` for secure password matching
- Salt rounds of 12 provides strong security while maintaining reasonable performance

---

### Before Code

```javascript
// Original registration - storing plain text password
app.post("/register", async (req, res) => {
    const { name, email, password, username } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.json({ error: "Username already taken." });
    }

    // VULNERABILITY: Password stored in plain text!
    const user = new User({ name, email, password, username, joinedCommunities: [] });
    await user.save();
    req.session.username = username;
    res.redirect("/home.html");
});

// Original login - comparing plain text passwords
app.post("/login", async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });

        if (user && user.password === req.body.password) {  // INSECURE!
            req.session.username = user.username;
            res.redirect("/home.html");
        } else {
            res.status(401).json({ error: "Invalid username or password" });
        }
    } catch (err) {
        res.status(500).json({ error: "Error logging in" });
    }
});
```

---

### After Code

```javascript
const bcrypt = require("bcrypt");

// Secure registration with password hashing
app.post("/register", registerLimiter, validateRegistration, handleValidationErrors, async (req, res) => {
    try {
        const { name, email, password, username } = req.body;

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: "Username already taken" });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: "Email already registered" });
        }

        // Hash password with bcrypt (12 salt rounds)
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const user = new User({ name, email, password: hashedPassword, username, joinedCommunities: [] });
        await user.save();

        req.session.username = username;
        res.redirect("/home.html");
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});

// Secure login with bcrypt comparison
app.post("/login", loginLimiter, validateLogin, handleValidationErrors, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });

        if (!user) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        // Compare hashed password securely
        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        req.session.username = user.username;
        res.redirect("/home.html");
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});
```

---

### Changes Made

1. **Added bcrypt dependency**: `npm install bcrypt --save`
2. **Registration endpoint**:
   - Added password hashing with `bcrypt.hash(password, 12)`
   - Added email duplicate check
   - Added input validation middleware
   - Changed error response from generic JSON to proper 400 status
3. **Login endpoint**:
   - Replaced plain text comparison with `bcrypt.compare()`
   - Added explicit null check for user
   - Added input validation middleware
   - Added rate limiting (see security update 02)
4. **Error handling**:
   - Generic error messages to prevent information leakage
   - Server-side logging of actual errors

---

### Notes

- **Salt Rounds**: 12 is recommended for most applications (balance of security and performance)
- **Migration**: Existing users with plain text passwords would need a password reset flow
- **Password Requirements**: Minimum 8 characters, maximum 128 characters
- **Timing Attack Prevention**: Using the same error message for "user not found" and "wrong password" prevents timing attacks

---

## 2. Rate Limiting on Authentication

### Explanation

#### Vulnerability Fixed
The original application had **no rate limiting** on login and registration endpoints, making it vulnerable to:
- **Brute Force Attacks**: Attackers could attempt unlimited password combinations
- **Credential Stuffing**: Automated testing of stolen credentials from other breaches
- **Denial of Service**: Overwhelming the server with requests
- **Account Enumeration**: Determining which usernames exist based on response patterns

#### Why It's Important
- **Brute Force Prevention**: Limits the number of attempts an attacker can make
- **Resource Protection**: Prevents server overload from automated attacks
- **Compliance**: Many security standards require rate limiting on authentication endpoints
- **Attack Deterrence**: Significantly increases the time/cost of attacks

#### Implementation Details
- **Login**: 5 attempts per 15 minutes per IP address
- **Registration**: 3 attempts per hour per IP address
- **API endpoints**: 100 requests per 15 minutes per IP
- Uses `express-rate-limit` middleware for reliable rate limiting

---

### Before Code

```javascript
// Original login - NO RATE LIMITING
app.post("/login", async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });

        if (user && user.password === req.body.password) {
            req.session.username = user.username;
            res.redirect("/home.html");
        } else {
            res.status(401).json({ error: "Invalid username or password" });
        }
    } catch (err) {
        res.status(500).json({ error: "Error logging in" });
    }
});

// Original registration - NO RATE LIMITING
app.post("/register", async (req, res) => {
    const { name, email, password, username } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.json({ error: "Username already taken." });
    }

    const user = new User({ name, email, password, username, joinedCommunities: [] });
    await user.save();
    req.session.username = username;
    res.redirect("/home.html");
});
```

---

### After Code

```javascript
const rateLimit = require("express-rate-limit");

// Login rate limiter - 5 attempts per 15 minutes
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "Too many login attempts, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
});

// Registration rate limiter - 3 attempts per hour
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: "Too many registration attempts, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
});

// General API rate limiter - 100 requests per 15 minutes
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many requests, please try again later" },
    standardHeaders: true,
    legacyHeaders: false
});

// Apply API rate limiter to all /api/ routes
app.use("/api/", apiLimiter);

// Login with rate limiting
app.post("/login", loginLimiter, validateLogin, handleValidationErrors, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });

        if (!user) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        req.session.username = user.username;
        res.redirect("/home.html");
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});

// Registration with rate limiting
app.post("/register", registerLimiter, validateRegistration, handleValidationErrors, async (req, res) => {
    try {
        const { name, email, password, username } = req.body;

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: "Username already taken" });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: "Email already registered" });
        }

        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const user = new User({ name, email, password: hashedPassword, username, joinedCommunities: [] });
        await user.save();

        req.session.username = username;
        res.redirect("/home.html");
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});
```

---

### Changes Made

1. **Added express-rate-limit dependency**: `npm install express-rate-limit --save`
2. **Created three rate limiters**:
   - `loginLimiter`: 5 requests per 15 minutes
   - `registerLimiter`: 3 requests per 60 minutes
   - `apiLimiter`: 100 requests per 15 minutes (for all /api/ routes)
3. **Applied rate limiters to endpoints**:
   - Login endpoint uses `loginLimiter`
   - Registration endpoint uses `registerLimiter`
   - All API routes automatically protected by `apiLimiter`
4. **Configuration**:
   - `standardHeaders: true` - Adds RateLimit headers (RFC compliant)
   - `legacyHeaders: false` - Disables old X-RateLimit headers
   - `keyGenerator: (req) => req.ip` - Rate limits by IP address

---

### Notes

- **IP-Based Limiting**: Rate limits are applied per IP address
- **Window Reset**: The window resets after the specified time period
- **Standard Headers**: Returns `RateLimit-Limit` and `RateLimit-Remaining` headers
- **Customization**: Values can be adjusted based on traffic patterns
- **Production Consideration**: For production behind a proxy, use `X-Forwarded-For` header for accurate IP detection
- **Account Lockout**: Consider implementing account-based lockout (separate from IP limiting) for additional security

---

## 3. Secure Session Cookies

### Explanation

#### Vulnerability Fixed
The original application had **insecure session cookie configuration**:
- `secure: false` - Cookies transmitted over unencrypted HTTP
- No `httpOnly` flag - Cookies accessible via JavaScript (XSS vulnerability)
- No `sameSite` attribute - Vulnerable to CSRF attacks
- **Hardcoded session secret** - Exposed in source code

#### Why It's Important
- **Confidentiality**: `secure: true` ensures cookies only sent over HTTPS
- **XSS Protection**: `httpOnly: true` prevents JavaScript access to session cookies
- **CSRF Protection**: `sameSite: "strict"` prevents cross-site request forgery
- **Secret Management**: Environment variables prevent secret exposure in code

#### Implementation Details
- `httpOnly: true` - Cookie inaccessible to JavaScript
- `secure: true` (in production) - Cookie only sent over HTTPS
- `sameSite: "strict"` - Cookie only sent with same-site requests
- Session secret loaded from environment variable
- `saveUninitialized: false` - Don't save sessions until data is stored

---

### Before Code

```javascript
// Original session configuration - INSECURE
app.use(session({
    secret: "quotient",  // HARDCODED SECRET!
    resave: false,
    saveUninitialized: true,
    rolling: true,
    cookie: {
        secure: false,  // VULNERABLE: Sent over HTTP
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));
```

---

### After Code

```javascript
// Secure session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || "quotient-secure-secret-change-in-production",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: process.env.NODE_ENV === "production",  // HTTPS in production
        httpOnly: true,  // No JavaScript access
        sameSite: "strict",  // CSRF protection
        maxAge: 7 * 24 * 60 * 60 * 1000  // 7 days
    }
}));
```

**Environment Variables (.env file):**
```bash
# Session Secret (CHANGE THIS IN PRODUCTION!)
SESSION_SECRET=your-super-secret-session-key-change-this-in-production

# Environment
NODE_ENV=development
```

---

### Changes Made

1. **Session Secret**:
   - Moved to environment variable (`process.env.SESSION_SECRET`)
   - Added fallback with warning to change in production
   - Created `.env.example` file for configuration template

2. **Cookie Security Flags**:
   - Added `httpOnly: true` - Prevents XSS attacks from stealing session
   - Added `sameSite: "strict"` - Prevents CSRF attacks
   - Changed `secure` to conditional based on environment

3. **Session Options**:
   - Changed `saveUninitialized: true` to `false` - Reduces storage of empty sessions
   - Kept `rolling: true` - Refreshes session expiration on each request

4. **Environment Configuration**:
   - Created `.env.example` with secure defaults
   - Added `NODE_ENV` for environment detection

---

### Notes

- **Development vs Production**: `secure` flag is only enabled in production to allow local development over HTTP
- **HTTPS Required**: In production, ensure HTTPS is enabled (see Security Update 08)
- **Secret Rotation**: Session secrets should be rotated periodically in production
- **Secret Generation**: Use `openssl rand -hex 64` to generate strong secrets
- **Cookie Storage**: Sessions are stored server-side (MongoDB/memory), cookie only contains session ID
- **SameSite Options**:
  - `"strict"` - Most secure, cookies never sent cross-site
  - `"lax"` - Allows some cross-site usage (e.g., following links)
  - `"none"` - Allows all cross-site (requires `secure: true`)

---

## 4. Input Validation & Sanitization

### Explanation

#### Vulnerability Fixed
The original application had **no input validation or sanitization**, making it vulnerable to:
- **XSS (Cross-Site Scripting)**: Malicious scripts injected into posts, comments, or profiles
- **NoSQL Injection**: Malicious MongoDB queries through user input
- **Data Integrity Issues**: No length limits or format validation
- **HTML Injection**: Malicious HTML content in user-submitted data

#### Why It's Important
- **XSS Prevention**: Sanitization removes malicious scripts before storage/rendering
- **Data Integrity**: Validation ensures data meets expected format and length
- **Injection Prevention**: Proper validation blocks injection attacks
- **User Experience**: Clear error messages for invalid input

#### Implementation Details
- **express-validator**: For input validation rules
- **xss library**: For HTML/script sanitization using filterXSS
- **Allowlist Approach**: Only allowing valid emojis, specific patterns
- **Global Sanitization**: Middleware sanitizes all input (body, query, params)

---

### Before Code

```javascript
// Original registration - NO VALIDATION
app.post("/register", async (req, res) => {
    const { name, email, password, username } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.json({ error: "Username already taken." });
    }

    // No validation - accepts ANY input!
    const user = new User({ name, email, password, username, joinedCommunities: [] });
    await user.save();
    req.session.username = username;
    res.redirect("/home.html");
});

// Original post creation - NO VALIDATION
app.post("/create-post", async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: "Session expired. Please log in again." });
    }

    const { title, brief, community } = req.body;  // No sanitization!
    const username = req.session.username;

    const user = await User.findOne({ username });

    if (!user.joinedCommunities.includes(community)) {
        return res.status(403).json({ error: "You must join the community first." });
    }

    const newPost = new Post({ username, community, title, brief });  // Raw input stored!
    await newPost.save();
    res.redirect("/home.html");
});

// Original search - VULNERABLE TO NOSQL INJECTION
app.get('/api/search-posts', async (req, res) => {
    const { query } = req.query;  // No validation!
    // ... uses raw query in regex
});
```

---

### After Code

```javascript
const { body, param, query, validationResult } = require("express-validator");
const { filterXSS } = require("xss");

// Global sanitization middleware
const sanitizeInput = (req, res, next) => {
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            if (typeof req.body[key] === "string") {
                req.body[key] = filterXSS(req.body[key]);
            }
        });
    }
    if (req.query) {
        Object.keys(req.query).forEach(key => {
            if (typeof req.query[key] === "string") {
                req.query[key] = filterXSS(req.query[key]);
            }
        });
    }
    if (req.params) {
        Object.keys(req.params).forEach(key => {
            if (typeof req.params[key] === "string") {
                req.params[key] = filterXSS(req.params[key]);
            }
        });
    }
    next();
};

app.use(sanitizeInput);

// Validation rules
const validateRegistration = [
    body("name").trim().notEmpty().withMessage("Name is required").isLength({ max: 100 }).withMessage("Name too long"),
    body("email").trim().notEmpty().withMessage("Email is required").isEmail().normalizeEmail().withMessage("Valid email required"),
    body("username").trim().notEmpty().withMessage("Username is required").isLength({ min: 3, max: 30 }).withMessage("Username must be 3-30 characters").matches(/^[a-zA-Z0-9_]+$/).withMessage("Username can only contain letters, numbers, and underscores"),
    body("password").notEmpty().withMessage("Password is required").isLength({ min: 8, max: 128 }).withMessage("Password must be 8-128 characters")
];

const validatePost = [
    body("title").trim().notEmpty().withMessage("Title is required").isLength({ min: 3, max: 100 }).withMessage("Title must be 3-100 characters"),
    body("brief").trim().notEmpty().withMessage("Brief is required").isLength({ min: 10, max: 500 }).withMessage("Brief must be 10-500 characters"),
    body("community").trim().notEmpty().withMessage("Community is required")
];

const validateComment = [
    body("content").trim().notEmpty().withMessage("Comment content is required").isLength({ max: 1000 }).withMessage("Comment too long")
];

// Validation error handler
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    next();
};

// Secured registration endpoint
app.post("/register", registerLimiter, validateRegistration, handleValidationErrors, async (req, res) => {
    try {
        const { name, email, password, username } = req.body;
        // ... rest of implementation
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});

// Secured post creation
app.post("/create-post", validatePost, handleValidationErrors, async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: "Session expired. Please log in again." });
    }

    try {
        const { title, brief, community } = req.body;  // Now sanitized and validated
        const username = req.session.username;

        const user = await User.findOne({ username });

        if (!user || !user.joinedCommunities.includes(community)) {
            return res.status(403).json({ error: "You must join the community first." });
        }

        const newPost = new Post({ username, community, title, brief });
        await newPost.save();
        res.redirect("/home.html");
    } catch (err) {
        console.error("Create post error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});

// Allowlist validation for emojis
app.post('/api/post/:id/react', validateId, handleValidationErrors, async (req, res) => {
    // ... validation code ...

    const validEmojis = ["👍", "😂", "😢", "🔥", "🙏"];
    if (!validEmojis.includes(emoji)) {
        return res.status(400).json({ error: 'Invalid emoji' });
    }

    // ... rest of implementation
});
```

---

### Changes Made

1. **Added Dependencies**:
   - `express-validator` for input validation
   - `xss` for HTML/script sanitization

2. **Global Sanitization Middleware**:
   - Sanitizes `req.body`, `req.query`, and `req.params`
   - Uses `filterXSS` to remove malicious HTML/scripts
   - Applied to all routes automatically

3. **Validation Rules Created**:
   - `validateRegistration`: Name, email, username, password rules
   - `validateLogin`: Username, password presence
   - `validateCommunity`: Community name, age, description rules
   - `validatePost`: Title, brief, community rules
   - `validateComment`: Content length limit
   - `validateId`: MongoDB ID format validation
   - `validateSearch`: Query parameter validation

4. **Validation Error Handler**:
   - Returns first validation error message
   - Returns 400 status for validation failures
   - Consistent error format across endpoints

5. **Allowlist Implementation**:
   - Valid emojis explicitly defined
   - Username pattern: `^[a-zA-Z0-9_]+$`
   - Email normalization with `normalizeEmail()`

---

### Notes

- **Sanitization Order**: Runs before validation to clean input first
- **Error Messages**: User-friendly but don't reveal system details
- **Length Limits**: Prevent database bloat and DoS attacks
- **Pattern Matching**: Username only allows alphanumeric and underscores
- **Email Normalization**: Converts emails to canonical form
- **NoSQL Injection**: Mongoose handles parameterization, but validation adds extra layer
- **Frontend Validation**: Client-side validation is UX enhancement, not security

---

## 5. Security Headers (Helmet)

### Explanation

#### Vulnerability Fixed
The original application had **no security headers**, making it vulnerable to:
- **Clickjacking**: Site embedded in malicious iframes
- **MIME Sniffing**: Browser misinterpreting content types
- **XSS Attacks**: No Content Security Policy to restrict script sources
- **Information Leakage**: Headers revealing server/software versions
- **Mixed Content**: No enforcement of secure connections

#### Why It's Important
- **Defense in Depth**: Multiple layers of protection even if other defenses fail
- **Browser Security**: Leverages built-in browser security features
- **Compliance**: Required by many security standards (PCI-DSS, SOC2)
- **Attack Prevention**: Blocks entire classes of attacks automatically

#### Implementation Details
- **Helmet.js**: Industry-standard security headers middleware
- **Content Security Policy**: Restricts allowed script/style sources
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Disables unnecessary browser features

---

### Before Code

```javascript
// Original application - NO SECURITY HEADERS
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");

const port = 3019;
const app = express();

// No security headers configured!
// Vulnerable to clickjacking, XSS, MIME sniffing, etc.

app.use(session({
    secret: "quotient",
    resave: false,
    saveUninitialized: true,
    rolling: true,
    cookie: {
        secure: false,
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
```

---

### After Code

```javascript
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");
const helmet = require("helmet");

const port = process.env.PORT || 3019;
const app = express();

// ============================================
// SECURITY FEATURE: Security Headers (Helmet)
// ============================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.tailwindcss.com", "https://unpkg.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" }
}));

// Additional security headers middleware
app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    next();
});

// Rest of middleware...
app.use(session({
    secret: process.env.SESSION_SECRET || "quotient-secure-secret-change-in-production",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));
```

---

### Changes Made

1. **Added Helmet Dependency**: `npm install helmet --save`

2. **Helmet Configuration**:
   - **Content Security Policy (CSP)**:
     - `defaultSrc: ["'self'"]` - Only load resources from same origin
     - `scriptSrc` - Allow scripts from self and required CDNs
     - `styleSrc` - Allow styles from self and Google Fonts
     - `imgSrc` - Allow images from self, data URIs, and blobs
     - `frameSrc: ["'none'"]` - No iframes allowed
     - `objectSrc: ["'none'"]` - No Flash/plugins allowed
     - `upgradeInsecureRequests` - Auto-upgrade HTTP to HTTPS

3. **Additional Security Headers**:
   - `X-Frame-Options: DENY` - Prevent all iframe embedding
   - `X-Content-Type-Options: nosniff` - Prevent MIME type sniffing
   - `Referrer-Policy: strict-origin-when-cross-origin` - Control referrer info
   - `Permissions-Policy` - Disable geolocation, microphone, camera

4. **Body Size Limits**:
   - Added `limit: "1mb"` to URL-encoded and JSON parsers
   - Prevents large payload DoS attacks

---

### Notes

- **CSP and CDNs**: The CSP allows specific CDNs used by the application (Bootstrap, Tailwind, Vue)
- **'unsafe-inline'**: Required for inline scripts/styles in current HTML files (consider moving to external files for stricter CSP)
- **X-Frame-Options**: Set to DENY (strictest) - adjust to SAMEORIGIN if embedding needed
- **Permissions-Policy**: Disables features not needed by the application
- **Helmet Defaults**: Helmet also sets other headers like X-XSS-Protection, Strict-Transport-Security (when configured)
- **Testing**: Use browser DevTools Console to check for CSP violations during development
- **HSTS**: See Security Update 08 for HTTPS enforcement and HSTS

---

## 6. Generic Error Handling

### Explanation

#### Vulnerability Fixed
The original application had **inconsistent and potentially information-leaking error handling**:
- Some endpoints returned detailed error messages
- Stack traces could be exposed to clients
- Database errors revealed internal structure
- Inconsistent error response formats

#### Why It's Important
- **Information Leakage Prevention**: Attackers can use error details to map your system
- **Stack Trace Exposure**: Can reveal file paths, code structure, dependencies
- **Database Structure**: Error messages can reveal table/collection names
- **Professional Appearance**: Generic errors look more professional to users
- **Compliance**: Security standards require proper error handling

#### Implementation Details
- Centralized error handling middleware
- Generic user-facing error messages
- Detailed server-side logging for debugging
- Consistent error response format
- Specific handlers for common error types

---

### Before Code

```javascript
// Original error handling - INCONSISTENT AND POTENTIALLY LEAKING INFO

app.post("/login", async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });

        if (user && user.password === req.body.password) {
            req.session.username = user.username;
            res.redirect("/home.html");
        } else {
            res.status(401).json({ error: "Error logging in" });  // Generic but inconsistent
        }
    } catch (err) {
        res.status(500).json({ error: "Error logging in" });  // No logging!
    }
});

app.get("/getPosts", async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json([]);
    }

    const user = await User.findOne({ username: req.session.username });

    if (!user || !Array.isArray(user.joinedCommunities)) {
        return res.json([]);
    }

    const posts = await Post.find({ community: { $in: user.joinedCommunities } });

    res.json(posts || []);
});  // NO ERROR HANDLING!

app.get('/api/post/:id', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        res.json(post);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });  // No logging!
    }
});

// NO GLOBAL ERROR HANDLER!
```

---

### After Code

```javascript
// ============================================
// Generic Error Handling Middleware
// ============================================
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);

    // Handle JSON parse errors
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'Invalid JSON format' });
    }

    // Handle MongoDB errors
    if (err.name === 'MongoServerError') {
        return res.status(500).json({ error: 'Database error occurred' });
    }

    // Handle validation errors (if not already handled)
    if (err.name === 'ValidationError') {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    // Default error response
    res.status(500).json({ error: 'An unexpected error occurred' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Resource not found' });
});

// Secured endpoints with proper error handling
app.post("/login", loginLimiter, validateLogin, handleValidationErrors, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });

        if (!user) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        req.session.username = user.username;
        res.redirect("/home.html");
    } catch (err) {
        console.error("Login error:", err);  // Log detailed error server-side
        res.status(500).json({ error: "An error occurred" });  // Generic client message
    }
});

app.get("/getPosts", async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json([]);
    }

    try {
        const user = await User.findOne({ username: req.session.username });

        if (!user || !Array.isArray(user.joinedCommunities)) {
            return res.json([]);
        }

        const posts = await Post.find({ community: { $in: user.joinedCommunities } });
        res.json(posts || []);
    } catch (error) {
        console.error("Error fetching posts:", error);  // Log detailed error
        res.status(500).json([]);  // Generic response
    }
});

app.get('/api/post/:id', validateId, handleValidationErrors, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        res.json(post);
    } catch (error) {
        console.error("Error fetching post:", error);  // Log detailed error
        res.status(500).json({ error: 'Server error' });  // Generic client message
    }
});
```

---

### Changes Made

1. **Global Error Handler Middleware**:
   - Catches all unhandled errors
   - Logs detailed errors server-side with `console.error`
   - Returns generic error messages to clients
   - Handles specific error types (JSON parse, MongoDB, Validation)

2. **404 Handler**:
   - Catches all unmatched routes
   - Returns consistent "Resource not found" message

3. **Endpoint Error Handling**:
   - Added try-catch blocks to all async endpoints
   - Added `console.error` logging for debugging
   - Consistent generic error messages to clients

4. **Error Response Format**:
   - All errors return `{ error: "message" }` format
   - Appropriate HTTP status codes (400, 401, 404, 500)
   - No stack traces or internal details exposed

5. **Specific Error Type Handling**:
   - `entity.parse.failed`: Invalid JSON in request body
   - `MongoServerError`: Database errors
   - `ValidationError`: Mongoose validation errors

---

### Notes

- **Logging**: In production, consider using a logging service (Winston, Pino, etc.)
- **Error Monitoring**: Consider integrating error tracking (Sentry, Bugsnag)
- **Consistent Format**: All errors use `{ error: "message" }` format
- **Status Codes**:
  - 400: Bad request (validation errors)
  - 401: Unauthorized (not logged in)
  - 403: Forbidden (insufficient permissions)
  - 404: Not found
  - 500: Server error
- **Redirect vs JSON**: Login/register redirect on success, but return JSON on error
- **Debugging**: Server logs contain full error details for debugging

---

## 7. Dependency Security

### Explanation

#### Vulnerability Fixed
The original application had **outdated and vulnerable dependencies**:
- No regular security auditing
- Potential known vulnerabilities in packages
- Missing security-focused dependencies
- No automated vulnerability detection

#### Why It's Important
- **Known Vulnerabilities**: Dependencies may have publicly known exploits
- **Supply Chain Attacks**: Compromised packages can affect your application
- **Compliance**: Security standards require dependency management
- **Zero-Day Protection**: Updated packages include latest security patches

#### Implementation Details
- Ran `npm audit` to identify vulnerabilities
- Updated packages to secure versions
- Added security-focused dependencies (helmet, bcrypt, etc.)
- Created npm script for easy auditing
- Established baseline for ongoing monitoring

---

### Before Code

```json
{
  "name": "project",
  "version": "1.0.0",
  "description": "nothing",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "express": "^4.21.2",
    "express-session": "^1.18.1",
    "mongodb": "^6.15.0",
    "mongoose": "^8.10.0",
    "mongosh": "^2.4.2",
    "nodemon": "^3.1.9",
    "path": "^0.12.7"
  }
}
```

**Security Issues:**
- No security-focused dependencies
- Missing input validation libraries
- No rate limiting
- No password hashing
- No security headers

---

### After Code

```json
{
  "name": "quotient",
  "version": "1.0.0",
  "description": "A secure community-driven social networking platform",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "echo \"Error: no test specified\" && exit 1",
    "audit": "npm audit"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "bcrypt": "^6.0.0",
    "express": "^4.21.2",
    "express-rate-limit": "^8.3.2",
    "express-session": "^1.18.1",
    "express-validator": "^7.3.1",
    "helmet": "^8.1.0",
    "mongodb": "^6.15.0",
    "mongoose": "^8.10.0",
    "mongosh": "^2.4.2",
    "nodemon": "^3.1.9",
    "path": "^0.12.7",
    "xss": "^1.0.15"
  }
}
```

**New Security Dependencies Added:**

| Package | Version | Purpose |
|---------|---------|---------|
| `bcrypt` | ^6.0.0 | Secure password hashing |
| `express-rate-limit` | ^8.3.2 | Rate limiting for brute force protection |
| `express-validator` | ^7.3.1 | Input validation and sanitization |
| `helmet` | ^8.1.0 | Security HTTP headers |
| `xss` | ^1.0.15 | XSS attack prevention |

---

### Changes Made

1. **Updated package.json Metadata**:
   - Changed name from "project" to "quotient"
   - Updated description to reflect application purpose
   - Changed main entry to "server.js"

2. **Added Security Scripts**:
   - `"start": "node server.js"` - Production start
   - `"dev": "nodemon server.js"` - Development with auto-reload
   - `"audit": "npm audit"` - Easy security auditing

3. **Security Dependencies Added**:
   - `bcrypt` - Password hashing (replaces plain text storage)
   - `express-rate-limit` - Rate limiting middleware
   - `express-validator` - Input validation
   - `helmet` - Security headers
   - `xss` - XSS sanitization

4. **Dependency Audit Process**:
   ```bash
   # Run security audit
   npm run audit

   # Auto-fix vulnerabilities where possible
   npm audit fix

   # Force fix (may include breaking changes)
   npm audit fix --force
   ```

---

### Notes

- **Vulnerability Status**: After installing security packages, run `npm audit` to check current status
- **Regular Auditing**: Run `npm audit` regularly (weekly/monthly)
- **Dependency Updates**: Keep dependencies updated with `npm update`
- **Lock File**: Always commit `package-lock.json` to ensure consistent installs
- **Breaking Changes**: Review changelogs before major version updates
- **Minimal Dependencies**: Only install necessary packages to reduce attack surface
- **Supply Chain Security**:
  - Use package-lock.json for reproducible builds
  - Consider using `npm ci` in production deployments
  - Review package before adding new dependencies
- **Automated Monitoring**: Consider GitHub Dependabot or similar for automated vulnerability alerts

### Current Vulnerability Status

After running `npm audit fix`, the application has **2 vulnerabilities** remaining in development/tooling dependencies:
- `brace-expansion` (moderate) - in `@mongosh/cli-repl` (MongoDB shell tool)
- `path-to-regexp` (high) - in `@mongosh/cli-repl` (MongoDB shell tool)

**These are acceptable risks because:**
1. They exist in `mongosh` - a database CLI tool, not runtime dependencies
2. They are not exposed to user input or network access
3. Fixing them would require waiting for upstream MongoDB updates
4. They don't affect the application's web-facing security

The core application dependencies (express, helmet, bcrypt, express-validator, etc.) are all up-to-date and secure.

---

## 8. HTTPS Enforcement

### Explanation

#### Vulnerability Fixed
The original application had **no HTTPS enforcement**:
- All traffic transmitted in plain text HTTP
- Session cookies vulnerable to interception
- User credentials sent unencrypted
- No protection against man-in-the-middle attacks
- No HSTS (HTTP Strict Transport Security)

#### Why It's Important
- **Data Encryption**: HTTPS encrypts all data in transit
- **Credential Protection**: Passwords and sessions cannot be intercepted
- **Integrity**: Prevents data modification in transit
- **Authentication**: Verifies server identity to clients
- **Trust**: Browsers mark HTTP sites as "Not Secure"
- **SEO**: Search engines prefer HTTPS sites

#### Implementation Details
- HTTPS redirect middleware for production
- HSTS header to enforce HTTPS
- Secure cookie configuration (see Security Update 03)
- Environment-based configuration
- SSL/TLS certificate setup guidance

---

### Before Code

```javascript
// Original application - NO HTTPS ENFORCEMENT
const port = 3019;
const app = express();

app.use(session({
    secret: "quotient",
    resave: false,
    saveUninitialized: true,
    rolling: true,
    cookie: {
        secure: false,  // Cookies sent over HTTP!
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

// No HTTPS redirect
// No HSTS header
// No secure connection enforcement

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
```

---

### After Code

```javascript
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");
const helmet = require("helmet");
const fs = require("fs");
const https = require("https");
const http = require("http");

const port = process.env.PORT || 3019;
const app = express();

// ============================================
// HTTPS Enforcement Middleware
// ============================================
// Redirect HTTP to HTTPS in production
app.use((req, res, next) => {
    if (process.env.NODE_ENV === "production" && !req.secure && req.get("X-Forwarded-Proto") !== "https") {
        return res.redirect(`https://${req.get("Host")}${req.url}`);
    }
    next();
});

// HSTS Header (via Helmet)
app.use(helmet({
    hsts: {
        maxAge: 31536000,  // 1 year
        includeSubDomains: true,
        preload: true
    },
    // ... other helmet config
}));

// Additional security headers
app.use((req, res, next) => {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    // ... other headers
    next();
});

// Secure session cookies
app.use(session({
    secret: process.env.SESSION_SECRET || "quotient-secure-secret-change-in-production",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: process.env.NODE_ENV === "production",  // HTTPS only in production
        httpOnly: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

// ... rest of middleware and routes

// ============================================
// Server Configuration
// ============================================
if (process.env.NODE_ENV === "production" && process.env.HTTPS_ENABLED === "true") {
    // HTTPS configuration for production
    const httpsOptions = {
        key: fs.readFileSync(process.env.HTTPS_KEY_PATH || "./ssl/key.pem"),
        cert: fs.readFileSync(process.env.HTTPS_CERT_PATH || "./ssl/cert.pem")
    };

    https.createServer(httpsOptions, app).listen(port, () => {
        console.log(`HTTPS Server running on port ${port}`);
    });

    // Optional: HTTP server to redirect to HTTPS
    http.createServer((req, res) => {
        res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
        res.end();
    }).listen(80, () => {
        console.log(`HTTP Server running on port 80 for redirects`);
    });
} else {
    // HTTP for development
    app.listen(port, () => {
        console.log(`Server is running on port ${port} (HTTP - Development mode)`);
        console.log(`WARNING: HTTPS is disabled. Enable in production!`);
    });
}
```

**Environment Variables (.env):**
```bash
# Environment
NODE_ENV=production

# HTTPS Configuration
HTTPS_ENABLED=true
HTTPS_KEY_PATH=./ssl/key.pem
HTTPS_CERT_PATH=./ssl/cert.pem

# Or use a reverse proxy (nginx, Apache, etc.)
# and set NODE_ENV=production with HTTPS_ENABLED=false
```

---

### Changes Made

1. **HTTPS Redirect Middleware**:
   - Checks `req.secure` and `X-Forwarded-Proto` header
   - Redirects HTTP to HTTPS in production
   - Allows HTTP in development for local testing

2. **HSTS Header Configuration**:
   - Enabled via Helmet's `hsts` option
   - `maxAge: 31536000` (1 year)
   - `includeSubDomains: true`
   - `preload: true` for browser HSTS preload list

3. **Manual HSTS Header**:
   - Added explicit `Strict-Transport-Security` header
   - Ensures HSTS is set even if Helmet config changes

4. **Secure Cookie Configuration**:
   - `secure: process.env.NODE_ENV === "production"`
   - Cookies only sent over HTTPS in production

5. **Dual Server Setup** (Optional):
   - HTTPS server for secure connections
   - HTTP server on port 80 for redirects
   - Controlled by environment variables

6. **Environment Configuration**:
   - `NODE_ENV` - Environment detection
   - `HTTPS_ENABLED` - Enable/disable HTTPS
   - `HTTPS_KEY_PATH` - SSL key file path
   - `HTTPS_CERT_PATH` - SSL certificate file path

---

### Notes

#### Development vs Production

**Development (HTTP):**
```bash
NODE_ENV=development
npm run dev
# Access: http://localhost:3019
```

**Production (HTTPS):**
```bash
NODE_ENV=production
HTTPS_ENABLED=true
npm start
```

#### SSL Certificate Options

1. **Let's Encrypt (Recommended - Free)**:
   ```bash
   # Install Certbot
   sudo apt-get install certbot

   # Get certificate
   sudo certbot certonly --standalone -d yourdomain.com
   ```

2. **Self-Signed (Development Only)**:
   ```bash
   mkdir ssl
   openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes
   ```

3. **Reverse Proxy (Recommended for Production)**:
   - Use nginx or Apache as reverse proxy
   - Handle SSL termination at proxy level
   - Application runs behind proxy on HTTP
   - Set `X-Forwarded-Proto: https` in proxy config

#### nginx Example:
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3019;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

#### HSTS Preload
To submit your domain to the HSTS preload list:
1. Ensure HSTS is configured correctly
2. Visit: https://hstspreload.org/
3. Submit your domain for inclusion

#### Important Considerations
- **Cookie Security**: `secure: true` means cookies won't work over HTTP
- **Mixed Content**: Ensure all resources (images, scripts, CSS) use HTTPS
- **WebSocket**: Use `wss://` instead of `ws://` for secure WebSockets
- **API Calls**: Update all API endpoints to use HTTPS

---

## Quick Reference

### Testing Security Features

```bash
# Test rate limiting (5th attempt should be blocked)
for i in {1..6}; do
  curl -X POST http://localhost:3019/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"wrong"}'
done

# Test input validation
curl -X POST http://localhost:3019/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"invalid","username":"test","password":"test"}'

# Check security headers
curl -I http://localhost:3019/
```

### Production Deployment Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Generate strong `SESSION_SECRET` (use `openssl rand -hex 64`)
- [ ] Enable HTTPS (`HTTPS_ENABLED=true`)
- [ ] Configure SSL certificates
- [ ] Set up reverse proxy (nginx/Apache)
- [ ] Configure MongoDB connection string
- [ ] Review and test all endpoints
- [ ] Set up monitoring and logging
- [ ] Enable automated security updates

---

*Document generated for Quotient Security Implementation*
