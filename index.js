// Dependencies
const express = require('express');
const userRoutes = require('./routes/userRoutes');
const authRoutes = require('./routes/authRoutes');
const rolesRoutes = require('./routes/roleRoutes');
const errorHandler = require('./middlewares/errorHandler');
const { pool, initializeDatabase } = require('./config/database');
const { isDatabaseConnected } = require('./utils/helper');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Initialization
const app = express();
const port = process.env.PORT || 3001;

// Security Middlewares
app.use(helmet()); // Adds various security headers

// Rate Limiting
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use(limiter); // Apply the rate limiting middleware to all requests

app.use(express.json());

// User routes
app.use('/users', userRoutes);

// Auth routes
app.use('/auth', authRoutes);

// Role routes
app.use('/roles', rolesRoutes);

// Error handler
app.use(errorHandler);

// Health check
app.use('/health', async(req, res) => {
    const dbConnected = await isDatabaseConnected();

    if(dbConnected){
        res.status(200).json({
            status: 'OK',
            message: 'User service is running',
            db: 'PostgreSQL'
        })
    } else {
        res.status(500).json({
            status: 'ERROR',
            message: 'User service is running, but database connection is down.',
            db: 'PostgreSQL'
        })
    }
});

function startServer(){
    app.listen(
        port, () => console.log(`User service is running on port ${port}`)
    );
}


initializeDatabase().then(() => {
    startServer();
});