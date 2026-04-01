const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const { body, param, query, validationResult } = require("express-validator");
const { filterXSS } = require("xss");

const port = process.env.PORT || 3019;
const app = express();

// ============================================
// SECURITY FEATURE 5: Security Headers (Helmet)
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

// ============================================
// SECURITY FEATURE 3: Secure Session Cookies
// ============================================
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

// ============================================
// SECURITY FEATURE 2: Rate Limiting
// ============================================
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "Too many login attempts, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: "Too many registration attempts, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many requests, please try again later" },
    standardHeaders: true,
    legacyHeaders: false
});

app.use("/api/", apiLimiter);

// Static files and body parsing
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));

// ============================================
// SECURITY FEATURE 4: Input Validation & Sanitization
// ============================================
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

const validateRegistration = [
    body("name").trim().notEmpty().withMessage("Name is required").isLength({ max: 100 }).withMessage("Name too long"),
    body("email").trim().notEmpty().withMessage("Email is required").isEmail().normalizeEmail().withMessage("Valid email required"),
    body("username").trim().notEmpty().withMessage("Username is required").isLength({ min: 3, max: 30 }).withMessage("Username must be 3-30 characters").matches(/^[a-zA-Z0-9_]+$/).withMessage("Username can only contain letters, numbers, and underscores"),
    body("password").notEmpty().withMessage("Password is required").isLength({ min: 8, max: 128 }).withMessage("Password must be 8-128 characters")
];

const validateLogin = [
    body("username").trim().notEmpty().withMessage("Username is required"),
    body("password").notEmpty().withMessage("Password is required")
];

const validateCommunity = [
    body("community").trim().notEmpty().withMessage("Community name is required").isLength({ max: 100 }).withMessage("Community name too long"),
    body("age").isInt({ min: 13, max: 21 }).withMessage("Age must be between 13 and 21"),
    body("description").trim().notEmpty().withMessage("Description is required").isLength({ max: 1000 }).withMessage("Description too long")
];

const validatePost = [
    body("title").trim().notEmpty().withMessage("Title is required").isLength({ min: 3, max: 100 }).withMessage("Title must be 3-100 characters"),
    body("brief").trim().notEmpty().withMessage("Brief is required").isLength({ min: 10, max: 500 }).withMessage("Brief must be 10-500 characters"),
    body("community").trim().notEmpty().withMessage("Community is required")
];

const validateComment = [
    body("content").trim().notEmpty().withMessage("Comment content is required").isLength({ max: 1000 }).withMessage("Comment too long")
];

const validateId = [
    param("id").isMongoId().withMessage("Invalid post ID")
];

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    next();
};

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/quotient';

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log("Connected to local MongoDB successfully");
    })
    .catch(err => {
        console.error("MongoDB connection error:", err);
    });

const db = mongoose.connection;
db.once("open", () => console.log("Database connection established successfully"));

// Schemas
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    username: String,
    joinedCommunities: [{ type: String }]
});

const User = mongoose.model("User", userSchema);

const postSchema = new mongoose.Schema({
    title: String,
    brief: String,
    community: String,
    username: String,
    createdAt: { type: Date, default: Date.now },
    reactions: {
        "👍": { count: { type: Number, default: 0 }, users: [{ type: String }] },
        "😂": { count: { type: Number, default: 0 }, users: [{ type: String }] },
        "😢": { count: { type: Number, default: 0 }, users: [{ type: String }] },
        "🔥": { count: { type: Number, default: 0 }, users: [{ type: String }] },
        "🙏": { count: { type: Number, default: 0 }, users: [{ type: String }] }
    },
    comments: [{
        username: String,
        content: String,
        createdAt: { type: Date, default: Date.now }
    }]
});

const communitySchema = new mongoose.Schema({
    community: String,
    age: Number,
    description: String,
    members: [{ type: String }]
});

const Post = mongoose.model("Post", postSchema);
const Community = mongoose.model("Community", communitySchema);

// Routes
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// ============================================
// SECURITY FEATURE 1: Password Hashing (Login)
// ============================================
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

// ============================================
// SECURITY FEATURE 1: Password Hashing (Register)
// ============================================
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

app.post("/create-community", validateCommunity, handleValidationErrors, async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: "Session expired. Please log in again." });
    }

    try {
        let { community, age, description } = req.body;

        if (!community.startsWith("quo.")) {
            community = `quo.${community}`;
        }

        const existingCommunity = await Community.findOne({ community });
        if (existingCommunity) {
            return res.status(400).json({ error: "Community name already exists!" });
        }

        const newCommunity = new Community({ community, age, description, members: [] });
        await newCommunity.save();
        res.redirect("/home.html");
    } catch (err) {
        console.error("Create community error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});

app.post("/create-post", validatePost, handleValidationErrors, async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: "Session expired. Please log in again." });
    }

    try {
        const { title, brief, community } = req.body;
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

app.post("/join-community", async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: "Session expired. Please log in again." });
    }

    try {
        const { community } = req.body;
        const user = await User.findOne({ username: req.session.username });
        const comm = await Community.findOne({ community });

        if (!comm) {
            return res.status(400).json({ error: "Community does not exist." });
        }

        if (!user.joinedCommunities.includes(community)) {
            user.joinedCommunities.push(community);
            await user.save();
            comm.members.push(user.username);
            await comm.save();
        }

        res.json({ message: "Joined community successfully!" });
    } catch (err) {
        console.error("Join community error:", err);
        res.status(500).json({ error: "An error occurred" });
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login.html");
});

app.get("/get-communities", async (req, res) => {
    try {
        const communities = await Community.find({}, "community");
        res.json(communities.map(c => c.community));
    } catch (error) {
        console.error("Error fetching communities:", error);
        res.status(500).json([]);
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
        console.error("Error fetching posts:", error);
        res.status(500).json([]);
    }
});

app.get("/get-user-communities", async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json([]);
    }

    try {
        const user = await User.findOne({ username: req.session.username });
        res.json(user?.joinedCommunities || []);
    } catch (error) {
        console.error("Error fetching user communities:", error);
        res.status(500).json([]);
    }
});

app.get('/api/current-user', (req, res) => {
    if (req.session.username) {
        res.json({ username: req.session.username });
    } else {
        res.status(401).json({ error: 'Not logged in' });
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
        console.error("Error fetching post:", error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/post/:id/comment', validateId, handleValidationErrors, validateComment, handleValidationErrors, async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        post.comments.push({
            username: req.session.username,
            content: req.body.content
        });

        await post.save();
        res.json(post);
    } catch (error) {
        console.error("Error adding comment:", error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/leave-community', async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: "Session expired. Please log in again." });
    }

    try {
        const { community } = req.body;
        const username = req.session.username;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        user.joinedCommunities = user.joinedCommunities.filter(c => c !== community);
        await user.save();

        const comm = await Community.findOne({ community });
        if (comm) {
            comm.members = comm.members.filter(m => m !== username);
            await comm.save();
        }

        res.json({ message: "Left community successfully" });
    } catch (error) {
        console.error("Error leaving community:", error);
        res.status(500).json({ error: "Server error" });
    }
});

app.post('/api/post/:id/react', validateId, handleValidationErrors, async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const { emoji } = req.body;
        const username = req.session.username;

        const validEmojis = ["👍", "😂", "😢", "🔥", "🙏"];
        if (!validEmojis.includes(emoji)) {
            return res.status(400).json({ error: 'Invalid emoji' });
        }

        const hasReacted = post.reactions[emoji].users.includes(username);

        if (hasReacted) {
            post.reactions[emoji].users = post.reactions[emoji].users.filter(user => user !== username);
            post.reactions[emoji].count--;
        } else {
            post.reactions[emoji].users.push(username);
            post.reactions[emoji].count++;
        }

        await post.save();
        res.json(post);
    } catch (error) {
        console.error("Error adding reaction:", error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/user/posts', async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    try {
        const username = req.session.username;
        const posts = await Post.find({ username });
        res.json(posts);
    } catch (error) {
        console.error('Error fetching user posts:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/search-posts', query("query").trim().notEmpty().withMessage("Search query required"), handleValidationErrors, async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    try {
        const { query } = req.query;
        const username = req.session.username;
        const user = await User.findOne({ username });

        if (!user || !Array.isArray(user.joinedCommunities)) {
            return res.json([]);
        }

        const posts = await Post.find({
            community: { $in: user.joinedCommunities },
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { brief: { $regex: query, $options: 'i' } }
            ]
        });

        res.json(posts || []);
    } catch (error) {
        console.error('Error searching posts:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/notifications', async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    try {
        const username = req.session.username;
        const userPosts = await Post.find({ username });

        if (!userPosts || userPosts.length === 0) {
            return res.json([]);
        }

        const notifications = [];

        userPosts.forEach(post => {
            if (post.comments && post.comments.length > 0) {
                post.comments.forEach(comment => {
                    notifications.push({
                        type: 'comment',
                        postId: post._id,
                        postTitle: post.title,
                        postBrief: post.brief,
                        username: comment.username,
                        content: comment.content,
                        createdAt: comment.createdAt
                    });
                });
            }

            Object.entries(post.reactions).forEach(([emoji, data]) => {
                if (data.users && data.users.length > 0) {
                    data.users.forEach(user => {
                        notifications.push({
                            type: 'reaction',
                            postId: post._id,
                            postTitle: post.title,
                            postBrief: post.brief,
                            username: user,
                            emoji: emoji,
                            createdAt: post.createdAt
                        });
                    });
                }
            });
        });

        notifications.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(notifications);
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// SECURITY FEATURE 6: Generic Error Handling
// ============================================
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);

    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'Invalid JSON format' });
    }

    res.status(500).json({ error: 'An unexpected error occurred' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Resource not found' });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
