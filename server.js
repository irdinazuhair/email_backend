import express from "express";
import cors from "cors";
import sgMail from "@sendgrid/mail";
import admin from "firebase-admin";

// ---- ENV VARS (set on Render) ----
const {
  SENDGRID_API_KEY,
  SENDGRID_FROM_EMAIL,
  FIREBASE_SERVICE_ACCOUNT_JSON,
  ALLOWED_ORIGIN
} = process.env;

sgMail.setApiKey(SENDGRID_API_KEY);

// Firebase Admin to verify Firebase ID tokens and read user email safely
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON))
});

const app = express();
app.use(express.json());

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  ALLOWED_ORIGIN
].filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // allow non-browser calls (Postman) and same-origin
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error("CORS blocked: " + origin));
  }
}));

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});


// POST /send-notification-email
// Body: { notificationUserId, subject, text }
app.post("/send-notification-email", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });

    // Verify caller is a logged-in Firebase user
    const decoded = await admin.auth().verifyIdToken(token);

    const { notificationUserId, subject, text } = req.body;

    // Security rule: only allow sending to the SAME user or staff action flows you control.
    // For now (simple): allow staff to notify others, but you must restrict usage in frontend.
    // Better: add role check using Firestore users doc.
    if (!notificationUserId || !subject || !text) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // Look up recipient email from Firebase Auth
    const userRecord = await admin.auth().getUser(notificationUserId);
    const toEmail = userRecord.email;
    if (!toEmail) return res.status(400).json({ error: "Recipient has no email" });

    await sgMail.send({
      to: toEmail,
      from: SENDGRID_FROM_EMAIL,
      subject,
      text
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to send email" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Email backend running on", PORT));
