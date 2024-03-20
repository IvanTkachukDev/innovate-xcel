# Getting Started

**Install Dependencies:** 
Make sure you have Node.js installed before starting. In the project directory, run the next command to install all dependencies:

### `npm install`

**Environment Variables:**
Create a .env file based on .env.example and add your actual data to it. This file might contain sensitive information like database credentials or API key. Ensure not to commit your .env file to version control


**Database Setup:**
Create the database. Use tables.sql file in the root directory to create the tables. You can import the SQL file via your preferred MySQL client or using command-line tools.

**Run the app:**
To start the server in development mode run the command:

### `npm start`

This command will run the server using nodemon, which automatically restarts the server whenever changes are detected in your files.
Runs the app in the development mode.\
Open [http://localhost:3000](http://localhost:3000) to view it in the browser.
The page will reload if you make edits.\
You will also see any lint errors in the console.



## Setting Up Google Text-to-Speech API

To use the Google Text-to-Speech API in this project, you need to obtain a JSON key from the Google Cloud Platform. Here are the steps to acquire the key:

1. **Create a Project in Google Cloud Platform**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/).
   - If you do not have a Google Cloud account, create one.
   - Create a new project or select an existing one.

2. **Enable the Text-to-Speech API**:
   - In the Console, go to "APIs & Services" > "Library".
   - Find the "Text-to-Speech API" and enable it for your project.

3. **Create Credentials**:
   - In the Console, navigate to the "Credentials" section.
   - Click on "Create credentials" and select "Service account key".
   - Follow the instructions to create a new service account or select an existing one.
   - After creating the service account, choose a role (e.g., "Owner" or "Editor").
   - Choose the JSON key format and click "Create". The key will be downloaded to your computer.

4. **Use the Key in Your Project**:
   - Place the downloaded JSON file in a secure and accessible location in your project.
   - Update your project’s configuration to reference the path to this file.
    `process.env.GOOGLE_APPLICATION_CREDENTIALS = "./key-file.json";`

⚠️ **Important**: Do not publish your JSON key in public repositories to ensure security.

For more detailed information, visit the [Google Cloud Text-to-Speech documentation](https://cloud.google.com/text-to-speech/docs).