require('dotenv').config()

const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser');

// components
const authRouter = require('./routes/auth')

const app = express()
const port = 3000

// Middleware
app.use(cors())
app.use(express.json());
app.use(bodyParser.json());

app.use('/innovate-xcel/api/user', authRouter);


app.listen(port, () => console.log(`The app listening on port ${port}!`))