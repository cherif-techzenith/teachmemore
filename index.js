// Dependencies
const express = require('express')
const userRoutes = require('./routes/userRoutes')
const errorHandler = require('./middlewares/errorHandler')
const { pool } = require('./config/database')
const { isDatabaseConnected } = require('./utils/helper')

// Initialization
const app = express()
const port = process.env.PORT || 3001

app.use(express.json())

// User routes
app.use('/users', userRoutes)

// Error handler
app.use(errorHandler)

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
})

app.listen(
    3000, () => console.log(`User service is running on ${port}`)
)