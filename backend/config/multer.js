// backend/config/multer.js

import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";


/* ==================================================
   __dirname para ES Modules
================================================== */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


/* ==================================================
   CARPETA DE ARCHIVOS MULTIMEDIA
================================================== */

const uploadPath = path.join(
  __dirname,
  "../uploads/multimedia"
);


/* ==================================================
   CREAR CARPETA SI NO EXISTE
================================================== */

if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, {
    recursive: true
  });
}


/* ==================================================
   CONFIGURACIÓN DE MULTER
================================================== */

const storageMultimedia = multer.diskStorage({

  destination: (req, file, cb) => {

    cb(
      null,
      uploadPath
    );

  },

  filename: (req, file, cb) => {

    cb(
      null,
      Date.now() + "-" + file.originalname
    );

  }

});


/* ==================================================
   MIDDLEWARE DE SUBIDA
================================================== */

export const uploadMultimedia =
  multer({
    storage: storageMultimedia
  });