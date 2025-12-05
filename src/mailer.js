const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

async function sendMail({ to, subject, html }) {
    try {
        const result = await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to,
            subject,
            html
        });
        console.log('Email envoyé à:', to);
        return result;
    } catch (error) {
        console.error('Erreur envoi email:', error);
        throw error;
    }
}

module.exports = { sendMail };