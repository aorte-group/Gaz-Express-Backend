process.on('unhandledRejection', console.error);
process.on('uncaughtException', console.error);

const express = require('express');
require('dotenv').config();

const app = express();
app.use(express.json());

// Routes
const authRoutes = require('./src/routes/auth');
app.use('/api/auth', authRoutes);

// Route de test
app.get('/', (req, res) => {
    res.send('API opérationnelle');
});

// Démarrage
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log("Serveur lancé sur le port " + PORT);
});
