// ==================================================
// backend/routes/documentosProspecto.js
// ==================================================

import express from "express";

import {
  subirDocumentoProspecto,
  listarDocumentosProspecto,
  obtenerArchivoDocumentoProspecto,
  eliminarDocumentoProspecto
} from "../controllers/documentosProspectoController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";

import {
  uploadDocumentoRH
} from "../config/multerDocumentosRH.js";


const router =
  express.Router();


// ==================================================
// LISTAR DOCUMENTOS
// GET /api/prospectos/:id/documentos
// ==================================================

router.get(
  "/:id/documentos",
  verifyToken,
  listarDocumentosProspecto
);


// ==================================================
// SUBIR DOCUMENTO
// POST /api/prospectos/:id/documentos
//
// FormData:
// file
// tipo_documento
// descripcion
// ==================================================

router.post(
  "/:id/documentos",
  verifyToken,

  (
    req,
    res,
    next
  ) => {

    uploadDocumentoRH.single(
      "file"
    )(
      req,
      res,
      error => {

        if (!error) {
          return next();
        }


        if (
          error.code ===
          "LIMIT_FILE_SIZE"
        ) {

          return res.status(400).json({
            success: false,
            message:
              "El archivo no puede superar los 10 MB"
          });
        }


        return res.status(400).json({
          success: false,
          message:
            error.message ||
            "No fue posible procesar el archivo"
        });
      }
    );
  },

  subirDocumentoProspecto
);


// ==================================================
// ABRIR DOCUMENTO PROTEGIDO
// GET
// /api/prospectos/:id/documentos/:idDocumento/archivo
// ==================================================

router.get(
  "/:id/documentos/:idDocumento/archivo",
  verifyToken,
  obtenerArchivoDocumentoProspecto
);


// ==================================================
// ELIMINAR DOCUMENTO
// DELETE
// /api/prospectos/:id/documentos/:idDocumento
// ==================================================

router.delete(
  "/:id/documentos/:idDocumento",
  verifyToken,
  eliminarDocumentoProspecto
);


export default router;