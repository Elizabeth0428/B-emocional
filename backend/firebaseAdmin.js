// backend/firebaseAdmin.js
import "dotenv/config";
import admin from "firebase-admin";
import fs from "fs";

// Verifica que exista el archivo de credenciales
const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;

if (!fs.existsSync(credPath)) {
  console.error(`❌ No se encontró el archivo de credenciales en: ${credPath}`);
  process.exit(1); // detener el servidor si no está el archivo
}

admin.initializeApp({
  credential: admin.credential.cert(credPath),
});

export const db = admin.firestore();
export const FieldValue = admin.firestore.FieldValue;
