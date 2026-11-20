// ==================================================
// backend/routes/psicologos.js
// ==================================================

import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";

import {
  fileURLToPath
} from "url";

import {
  listarPsicologos,
  listarAreasAtencion,
  obtenerMiPerfilPsicologo,
  actualizarMiPerfilPsicologo,
  subirFotoPerfilPsicologo
} from "../controllers/psicologoController.js";

import {
  listarMisCanalizacionesPsicologo,
  aceptarCanalizacionPsicologo,
  rechazarCanalizacionPsicologo
} from "../controllers/canalizacionPsicologoController.js";

import {
  verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";


const router =
  express.Router();


// ==================================================
// __dirname PARA ES MODULES
// ==================================================

const __filename =
  fileURLToPath(
    import.meta.url
  );


const __dirname =
  path.dirname(
    __filename
  );


// ==================================================
// CARPETA DE FOTOS
//
// backend/uploads/imagenes/psicologos
// ==================================================

const carpetaFotos =
  path.join(
    __dirname,
    "..",
    "uploads",
    "imagenes",
    "psicologos"
  );


if (
  !fs.existsSync(
    carpetaFotos
  )
) {

  fs.mkdirSync(
    carpetaFotos,
    {
      recursive: true
    }
  );

}


// ==================================================
// CONFIGURACIÓN DE MULTER
// ==================================================

const storage =
  multer.diskStorage({

    destination:
      (
        req,
        file,
        cb
      ) => {

        cb(
          null,
          carpetaFotos
        );

      },


    filename:
      (
        req,
        file,
        cb
      ) => {

        const extension =
          path
            .extname(
              file.originalname
            )
            .toLowerCase();


        const idUsuario =
          req.user?.id_usuario ||
          "usuario";


        const nombreArchivo =
          `psicologo-${idUsuario}-${Date.now()}${extension}`;


        cb(
          null,
          nombreArchivo
        );

      }

  });


// ==================================================
// VALIDAR TIPO DE ARCHIVO
// ==================================================

const fileFilter =
  (
    req,
    file,
    cb
  ) => {

    const tiposPermitidos = [
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/webp"
    ];


    if (
      tiposPermitidos.includes(
        file.mimetype
      )
    ) {

      return cb(
        null,
        true
      );

    }


    return cb(
      new Error(
        "Formato de imagen no permitido. Usa JPG, PNG o WEBP."
      ),
      false
    );

  };


// ==================================================
// CONFIGURAR UPLOAD
//
// Máximo 5 MB
// ==================================================

const uploadFoto =
  multer({

    storage,

    fileFilter,

    limits: {
      fileSize:
        5 * 1024 * 1024
    }

  });


// ==================================================
// CATÁLOGO DE ÁREAS
//
// GET /api/psicologos/areas-atencion
// ==================================================

router.get(
  "/areas-atencion",
  verifyToken,
  listarAreasAtencion
);


// ==================================================
// FOTO PROFESIONAL
//
// POST /api/psicologos/mi-perfil/foto
//
// Campo multipart:
// foto
// ==================================================

router.post(
  "/mi-perfil/foto",
  verifyToken,
  uploadFoto.single(
    "foto"
  ),
  subirFotoPerfilPsicologo
);


// ==================================================
// MI PERFIL PROFESIONAL
//
// GET /api/psicologos/mi-perfil
// ==================================================

router.get(
  "/mi-perfil",
  verifyToken,
  obtenerMiPerfilPsicologo
);


// ==================================================
// ACTUALIZAR MI PERFIL
//
// PUT /api/psicologos/mi-perfil
// ==================================================

router.put(
  "/mi-perfil",
  verifyToken,
  actualizarMiPerfilPsicologo
);


// ==================================================
// CANALIZACIONES RECIBIDAS DEL PSICÓLOGO
//
// GET
// /api/psicologos/canalizaciones
// ==================================================

router.get(
  "/canalizaciones",
  verifyToken,
  listarMisCanalizacionesPsicologo
);


// ==================================================
// ACEPTAR CANALIZACIÓN
//
// PUT
// /api/psicologos/canalizaciones/:idOpcion/aceptar
// ==================================================

router.put(
  "/canalizaciones/:idOpcion/aceptar",
  verifyToken,
  aceptarCanalizacionPsicologo
);


// ==================================================
// RECHAZAR CANALIZACIÓN
//
// PUT
// /api/psicologos/canalizaciones/:idOpcion/rechazar
// ==================================================

router.put(
  "/canalizaciones/:idOpcion/rechazar",
  verifyToken,
  rechazarCanalizacionPsicologo
);


// ==================================================
// LISTAR PSICÓLOGOS
//
// GET /api/psicologos
//
// MASTER:
// - todos.
//
// ADMIN NORMAL CLÍNICA:
// - únicamente los que creó.
// ==================================================

router.get(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarPsicologos
);


// ==================================================
// MANEJO DE ERRORES MULTER
// ==================================================

router.use(
  (
    error,
    req,
    res,
    next
  ) => {

    if (
      error instanceof
      multer.MulterError
    ) {

      if (
        error.code ===
        "LIMIT_FILE_SIZE"
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "La imagen no puede pesar más de 5 MB."

          });

      }


      return res
        .status(400)
        .json({

          success:
            false,

          message:
            error.message

        });

    }


    if (
      error?.message?.includes(
        "Formato de imagen"
      )
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            error.message

        });

    }


    next(
      error
    );

  }
);


export default router;