const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { generateRandomToken } = require('../utils/tokens');
const { sendMail } = require('../mailer');
require('dotenv').config();

// --------------------------- REGISTER ---------------------------

router.post('/register', async (req, res) => {
    try {
        const { email, password, phone_number, user_type } = req.body;

        // Validation des champs requis
        if (!email || !password || !phone_number || !user_type) {
            return res.status(400).json({ error: "Tous les champs sont obligatoires" });
        }

        // Vérifier si l'utilisateur existe déjà
        const exists = await db.query(
            "SELECT user_id FROM users WHERE email=$1",
            [email]
        );

        if (exists.rows.length > 0) {
            return res.status(400).json({ error: "Email déjà enregistré" });
        }

        // Vérifier si le numéro existe
        const phoneExists = await db.query(
            "SELECT user_id FROM users WHERE phone_number=$1",
            [phone_number]
        );

        if (phoneExists.rows.length > 0) {
            return res.status(400).json({ error: "Numéro déjà utilisé" });
        }

        // Hash du mot de passe
        const hashedPassword = await bcrypt.hash(
            password,
            Number(process.env.BCRYPT_SALT_ROUNDS) || 10
        );

        // Générer le token de vérification (valide 24h)
        const verificationToken = generateRandomToken(32);
        const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Insertion utilisateur
        const result = await db.query(
            `INSERT INTO users (email, phone_number, password_hash, user_type, verification_token, verification_token_expires)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING user_id`,
            [email, phone_number, hashedPassword, user_type, verificationToken, verificationTokenExpires]
        );

        const userId = result.rows[0].user_id;

        // Envoyer l'email de vérification
        try {
            const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}`;
            
            await sendMail({
                to: email,
                subject: "Vérification de votre email - E-Society",
                html: `
                    <h2>Bienvenue sur E-Society !</h2>
                    <p>Merci de vous être inscrit. Veuillez vérifier votre adresse email en cliquant sur le lien ci-dessous :</p>
                    <a href="${verificationUrl}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Vérifier mon email
                    </a>
                    <p>Ce lien expirera dans 24 heures.</p>
                    <p>Si vous n'avez pas créé de compte, veuillez ignorer cet email.</p>
                `
            });
            
            console.log(" Email de vérification envoyé à:", email);
            console.log(" Token de vérification:", verificationToken);
            
        } catch (emailError) {
            console.error(" Erreur envoi email:", emailError);
        }

        res.json({
            message: "Inscription réussie. Un email de vérification a été envoyé.",
            user_id: userId,
            verification_sent: true,
            debug_token: verificationToken // Pour tests Postman
        });

    } catch (err) {
        console.error(" REGISTER ERROR:", err);
        res.status(500).json({ error: "Erreur serveur lors de l'inscription" });
    }
});

// --------------------------- VERIFY EMAIL ---------------------------

router.post('/verify-email', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ error: "Token manquant" });
        }

        // Chercher l'utilisateur avec ce token valide
        const result = await db.query(
            `SELECT user_id, verification_token_expires 
             FROM users 
             WHERE verification_token = $1 AND email_verified = false`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Token invalide ou email déjà vérifié" });
        }

        const user = result.rows[0];

        // Vérifier l'expiration
        if (new Date() > new Date(user.verification_token_expires)) {
            return res.status(400).json({ error: "Token expiré" });
        }

        // Activer le compte
        await db.query(
            `UPDATE users 
             SET email_verified = true, 
                 verification_token = NULL,
                 verification_token_expires = NULL
             WHERE user_id = $1`,
            [user.user_id]
        );

        console.log("Email vérifié pour user_id:", user.user_id);

        res.json({ 
            message: "Email vérifié avec succès ! Vous pouvez maintenant vous connecter.",
            verified: true 
        });

    } catch (err) {
        console.error(" VERIFY EMAIL ERROR:", err);
        res.status(500).json({ error: "Erreur serveur lors de la vérification" });
    }
});

// --------------------------- RESEND VERIFICATION ---------------------------

router.post('/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: "Email requis" });
        }

        const result = await db.query(
            "SELECT user_id, email_verified FROM users WHERE email = $1",
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Email non trouvé" });
        }

        const user = result.rows[0];

        if (user.email_verified) {
            return res.status(400).json({ error: "Email déjà vérifié" });
        }

        // Générer un nouveau token
        const verificationToken = generateRandomToken(32);
        const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Mettre à jour le token
        await db.query(
            `UPDATE users 
             SET verification_token = $1, verification_token_expires = $2 
             WHERE user_id = $3`,
            [verificationToken, verificationTokenExpires, user.user_id]
        );

        // Renvoyer l'email
        try {
            const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}`;
            
            await sendMail({
                to: email,
                subject: "Renouvellement - Vérification de votre email - E-Society",
                html: `
                    <h2>Renouvellement du lien de vérification</h2>
                    <p>Voici votre nouveau lien de vérification :</p>
                    <a href="${verificationUrl}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Vérifier mon email
                    </a>
                    <p>Ce lien expirera dans 24 heures.</p>
                `
            });
            
            console.log(" Email de vérification renvoyé à:", email);
            console.log(" Nouveau token:", verificationToken);
            
        } catch (emailError) {
            console.error(" Erreur envoi email:", emailError);
            return res.status(500).json({ error: "Erreur lors de l'envoi de l'email" });
        }

        res.json({ 
            message: "Email de vérification renvoyé avec succès",
            resent: true 
        });

    } catch (err) {
        console.error(" RESEND VERIFICATION ERROR:", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// --------------------------- LOGIN ---------------------------

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: "Email et mot de passe requis" });
        }

        const result = await db.query(
            "SELECT user_id, password_hash, email_verified FROM users WHERE email=$1",
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Identifiants invalides" });
        }

        const user = result.rows[0];

        // Vérifier mot de passe
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(400).json({ error: "Identifiants invalides" });
        }

        // Vérification email
        if (!user.email_verified) {
            return res.status(403).json({ 
                error: "Email non vérifié",
                needs_verification: true 
            });
        }

        // Génération JWT
        const token = jwt.sign(
            { user_id: user.user_id, email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION || '24h' }
        );

        // Mise à jour dernière connexion
        await db.query(
            "UPDATE users SET last_login_at = NOW() WHERE user_id=$1",
            [user.user_id]
        );

        console.log(" Connexion réussie pour:", email);

        res.json({ 
            token,
            message: "Connexion réussie..."
        });

    } catch (err) {
        console.error(" LOGIN ERROR:", err);
        res.status(500).json({ error: "Erreur serveur lors de la connexion" });
    }
});

// --------------------------- FORGOT PASSWORD ---------------------------

router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: "Email requis" });
        }

        const result = await db.query(
            "SELECT user_id FROM users WHERE email=$1",
            [email]
        );

        if (result.rows.length === 0) {
            // Pour la sécurité, on ne révèle pas si l'email existe
            return res.json({ 
                message: "Si l'email existe, un lien de réinitialisation a été envoyé" 
            });
        }

        const user = result.rows[0];

        // Générer le token de reset (valide 1h)
        const resetToken = generateRandomToken(32);
        const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000);

        // Enregistrer le token
        await db.query(
            `UPDATE users 
             SET reset_token = $1, reset_token_expires = $2 
             WHERE user_id = $3`,
            [resetToken, resetTokenExpires, user.user_id]
        );

        // Envoyer l'email
        try {
            const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
            
            await sendMail({
                to: email,
                subject: "Réinitialisation de votre mot de passe - E-Society",
                html: `
                    <h2>Réinitialisation de mot de passe</h2>
                    <p>Vous avez demandé la réinitialisation de votre mot de passe. Cliquez sur le lien ci-dessous :</p>
                    <a href="${resetUrl}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Réinitialiser mon mot de passe
                    </a>
                    <p>Ce lien expirera dans 1 heure.</p>
                    <p>Si vous n'avez pas fait cette demande, ignorez cet email.</p>
                `
            });
            
            console.log(" Email de reset envoyé à:", email);
            console.log(" Token de reset:", resetToken);
            
        } catch (emailError) {
            console.error(" Erreur envoi email:", emailError);
            return res.status(500).json({ error: "Erreur lors de l'envoi de l'email" });
        }

        res.json({ 
            message: "Si l'email existe, un lien de réinitialisation a été envoyé"
        });

    } catch (err) {
        console.error(" FORGOT PASSWORD ERROR:", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// --------------------------- RESET PASSWORD ---------------------------

router.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ error: "Token et nouveau mot de passe requis" });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: "Le mot de passe doit contenir au moins 6 caractères" });
        }

        // Chercher l'utilisateur avec ce token valide
        const result = await db.query(
            `SELECT user_id, reset_token_expires 
             FROM users 
             WHERE reset_token = $1`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Token invalide" });
        }

        const user = result.rows[0];

        // Vérifier l'expiration
        if (new Date() > new Date(user.reset_token_expires)) {
            return res.status(400).json({ error: "Token expiré" });
        }

        // Hash du nouveau mot de passe
        const hashedPassword = await bcrypt.hash(
            newPassword,
            Number(process.env.BCRYPT_SALT_ROUNDS) || 10
        );

        // Mettre à jour le mot de passe et effacer le token
        await db.query(
            `UPDATE users 
             SET password_hash = $1, 
                 reset_token = NULL,
                 reset_token_expires = NULL
             WHERE user_id = $2`,
            [hashedPassword, user.user_id]
        );

        console.log(" Mot de passe reset pour user_id:", user.user_id);

        res.json({ 
            message: "Mot de passe mis à jour avec succès" 
        });

    } catch (err) {
        console.error(" RESET PASSWORD ERROR:", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

module.exports = router;