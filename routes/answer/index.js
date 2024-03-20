const router = require('express').Router();
const OpenAI = require('openai')

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

process.env.GOOGLE_APPLICATION_CREDENTIALS = "./key-file.json";


router.post('/generate', async (req, res) => {

});

router.post('/synthesize', async (req, res) => {

});