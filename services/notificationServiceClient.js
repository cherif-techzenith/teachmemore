// services/notificationServiceClient.js
require('dotenv').config(); // Ensure environment variables are loaded
const axios = require('axios');

const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL;
// const NOTIFICATION_SERVICE_API_KEY = process.env.NOTIFICATION_SERVICE_API_KEY; // If you use an API key

// Sends an email verification notification.
const sendEmailVerification = async (email, username, verificationUrl) => {
    if (!NOTIFICATION_SERVICE_URL) {
        console.warn("NOTIFICATION_SERVICE_URL n'est pas configuré. Notification par e-mail ignorée.");
        console.log('--- SIMULATION DE VÉRIFICATION D\'E-MAIL (Service de notification non configuré) ---');
        console.log(`À : ${email}`);
        console.log(`Nom d'utilisateur : ${username}`);
        console.log(`Objet : Vérifiez votre adresse e-mail`);
        console.log(`URL de vérification : ${verificationUrl}`);
        console.log(`-----------------------------------------------------------------`);
        return;
    }

    const payload = {
        type: 'EMAIL_VERIFICATION',
        recipient: email,
        data: {
            username: username,
            verificationLink: verificationUrl,
        },
    };

    try {
        console.log(`Tentative d'envoi de la vérification d'e-mail à ${email} via le service de notification : ${NOTIFICATION_SERVICE_URL}/send`);
        await axios.post(`${NOTIFICATION_SERVICE_URL}/send`, payload, {
            // headers: {
            //     'Authorization': `Bearer ${NOTIFICATION_SERVICE_API_KEY}`, // If using an API key
            //     'Content-Type': 'application/json',
            // }
        });
        console.log(`Demande de vérification d'e-mail envoyée avec succès pour ${email}.`);
    } catch (error) {
        console.error(`Erreur lors de l'envoi de la vérification d'e-mail à ${email} via le service de notification :`, error.response ? error.response.data : error.message);
    }
};

// You can add other notification functions here, e.g., sendPasswordResetEmail

module.exports = {
    sendEmailVerification,
};