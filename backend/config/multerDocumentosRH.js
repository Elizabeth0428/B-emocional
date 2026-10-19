// ==================================================
// backend/config/multerDocumentosRH.js
// ==================================================

import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// IMPORTANTE:
// No guardar dentro de /uploads porque /uploads es público.
export const documentosRHPath = path.join(
  __dirname,
  "../storage/documentos-prospectos"
);

if (!fs.existsSync(documentosRHPath)) {
  fs.mkdirSync(documentosRHPath, {
    recursive: true
  });
}

const extensionesPermitidas = new Set([
  ".pdf",
  ".jpg",
  ".jpeg",
  ".png",
  ".doc",
  ".docx"
]);

const mimePermitidos = new Set([
  "application/pdf",
  "image/jpeg",
  "image/png",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
]);

const storage = multer.diskStorage({

  destination: (_req, _file, cb) => {
    cb(null, documentosRHPath);
  },

  filename: (_req, file, cb) => {

    const extension =
      path.extname(file.originalname)
        .toLowerCase();

    const nombreSeguro =
      `${Date.now()}-${crypto.randomBytes(12).toString("hex")}${extension}`;

    cb(null, nombreSeguro);
  }

});

const fileFilter = (_req, file, cb) => {

  const extension =
    path.extname(file.originalname)
      .toLowerCase();

  if (
    !extensionesPermitidas.has(extension) ||
    !mimePermitidos.has(file.mimetype)
  ) {
    return cb(
      new Error(
        "Tipo de archivo no permitido. Solo PDF, JPG, JPEG, PNG, DOC y DOCX."
      )
    );
  }

  cb(null, true);
};

export const uploadDocumentoRH = multer({

  storage,

  limits: {
    fileSize: 10 * 1024 * 1024
  },

  fileFilter

});