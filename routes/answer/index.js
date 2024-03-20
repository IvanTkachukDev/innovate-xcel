const router = require('express').Router();
const OpenAI = require('openai')
const textToSpeech = require('@google-cloud/text-to-speech');

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

const client = new textToSpeech.TextToSpeechClient();

process.env.GOOGLE_APPLICATION_CREDENTIALS = "./key-file.json";


const mainPrompt = `Welcome! I am your virtual assistant here to provide assistance regarding life insurance. My aim is to offer clear and helpful information about insurance options, assist with inquiries, and guide you through the decision-making process. Here's what I can do for you:
                    - Answer any questions about life insurance policies and their benefits.
                    - Explain life insurance terms and concepts to ensure you understand your options.
                    - Assist in assessing your insurance needs based on your personal circumstances, like family, finances, and future goals.
                    - Discuss the various types of life insurance available, including term, whole, universal, and variable, to find the best fit for you.
                    - Guide you through the application process step by step.
                    - Assist in determining the coverage amount and designating beneficiaries.
                    - Provide information in the form of tables for clarity.
                    - Explain the claims process and what to expect when making a claim.
                    Remember, my goal is to understand your needs and help you secure suitable coverage for your life's journey. Let's work together to ensure you and your loved ones are protected. How may I assist you today?`


router.post('/generate', async (req, res) => {
    const completion = await openai.chat.completions.create({
        messages: [
            { role: "system", content: mainPrompt },
            { role: "user", content: req.body.text }
        ],
        temperature: 0,
        top_p: 0,
        max_tokens: 555,
        frequency_penalty: .6,
        model: process.env.AI_MODEL,
    });

    let firstParagraph = completion.choices[0].message.content.split('\n\n|') // separate first paragraph from table + other text

    let tableAnswer = '';
    if (firstParagraph[1]) {
        tableAnswer = firstParagraph[1].split('\n\n') // separate table from other text

        firstParagraph = [firstParagraph[0] + tableAnswer[1]]

        tableAnswer = '|' + tableAnswer[0]
    }

    res.send({
        textAnswer: firstParagraph[0],
        tableAnswer
    });
});

router.post('/synthesize', async (req, res) => {
    try {
        const request = {
            input: { text: req.body.text },
            voice: { languageCode: 'en-US', name: 'en-US-Standard-F' },
            audioConfig: {
                audioEncoding: 'MP3',
                effectsProfileId: ['small-bluetooth-speaker-class-device'],
                pitch: 0,
                speakingRate: 1
            },
        };

        const [response] = await client.synthesizeSpeech(request);
        const audioContent = response.audioContent;
        res.set('Content-Type', 'audio/pm3');
        res.send(audioContent);
    } catch (error) {
        console.error(`Error at /synthesize endpoint: ${error}`);
        res.status(500).send('Error in synthesizing speech');
    }
});