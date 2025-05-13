const express = require('express')

const app = express()
const UserRoutes = require('./routes/UserRoutes')

app.use(express.json())

app.use('/users', UserRoutes)

app.listen(
    3000, () => console.log('App is running')
)