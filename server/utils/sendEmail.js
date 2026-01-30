const { Resend } = require('resend');


const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = 'Se-Docx <noreply@pinch-your-pins.site>';

const sendEmail = async (options) => {
    try {
        console.log("Attempting to send email to:", options.email);
        console.log("Using API Key:", process.env.RESEND_API_KEY ? "Present" : "MISSING");

        const data = await resend.emails.send({
            from: FROM_EMAIL,
            to: options.email,
            subject: options.subject,
            html: options.message
        });

        if (data.error) {
            console.error("Resend API Error:", data.error);
            throw new Error(data.error.message);
        }

        console.log("Email Sent. ID:", data.data ? data.data.id : data.id);
        return data;
    } catch (error) {
        console.error("Resend Error:", error);
        throw new Error("Email could not be sent");
    }
};

module.exports = sendEmail;