const mysql = require('mysql');


// mysql config
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_DBNAME,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD
});

// connect to db
db.connect((e) => {
    if (e) {
        console.log("DB connection error:", e);
    } else {
        console.log("MySQL is connected");
    }
});

module.exports = db;