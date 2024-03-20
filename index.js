require('dotenv').config()

const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser');
const answerRouter = require('./routes/answer')
const checkJwtToken = require('./middleware/jwtToken')

// components
const authRouter = require('./routes/auth')

const app = express()
const port = 3000

// Middleware
app.use(cors())
app.use(express.json());
app.use(bodyParser.json());
app.use(checkJwtToken);

app.use('/innovate-xcel/api/user', authRouter);
app.use('/innovate-xcel/api/answer', answerRouter);


app.listen(port, () => console.log(`The app listening on port ${port}!`))