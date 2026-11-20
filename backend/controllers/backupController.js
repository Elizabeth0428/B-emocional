// ==================================================
// backend/controllers/backupController.js
// ==================================================

import fs from "fs";

import {
  crearBackupBD,
  listarBackups,
  limpiarBackupsAntiguos,
  obtenerRutaBackup,
  backupConfig
} from "../svc/backupService.js";


// ==================================================
// VALIDAR MASTER
// ==================================================

function esMaster(
  req
) {

  const role =
    Number(
      req.user?.role
    );


  const rol =
    String(
      req.user?.rol ||
      ""
    )
      .trim()
      .toLowerCase();


  const tipoAdmin =
    String(
      req.user?.tipo_admin ||
      ""
    )
      .trim()
      .toLowerCase();


  return (
    role === 1 &&
    rol === "admin" &&
    tipoAdmin === "master"
  );

}


// ==================================================
// VALIDACIÓN
// ==================================================

function validarMaster(
  req,
  res
) {

  if (
    !req.user
  ) {

    res
      .status(401)
      .json({
        success:
          false,

        message:
          "Debes iniciar sesión."
      });


    return false;

  }


  if (
    !esMaster(
      req
    )
  ) {

    res
      .status(403)
      .json({
        success:
          false,

        code:
          "SOLO_MASTER",

        message:
          "Esta función está disponible únicamente para el Administrador Master."
      });


    return false;

  }


  return true;

}


// ==================================================
// LISTAR RESPALDOS
// GET /api/backups
// ==================================================

export async function obtenerBackups(
  req,
  res
) {

  try {

    if (
      !validarMaster(
        req,
        res
      )
    ) {

      return;

    }


    const backups =
      listarBackups();


    return res.json({

      success:
        true,

      total:
        backups.length,

      dias_retencion:
        backupConfig
          .diasRetencion,

      backups

    });

  }

  catch (
    error
  ) {

    console.error(
      "❌ Error listando respaldos:",
      error
    );


    return res
      .status(500)
      .json({
        success:
          false,

        message:
          "No se pudieron obtener los respaldos."
      });

  }

}


// ==================================================
// CREAR RESPALDO MANUAL
// POST /api/backups
// ==================================================

export async function crearBackupManual(
  req,
  res
) {

  try {

    if (
      !validarMaster(
        req,
        res
      )
    ) {

      return;

    }


    const backup =
      await crearBackupBD({
        origen:
          "manual"
      });


    /*
      Solo limpiamos después de confirmar
      que el nuevo respaldo fue creado.
    */

    const limpieza =
      limpiarBackupsAntiguos(
        backupConfig
          .diasRetencion
      );


    return res
      .status(201)
      .json({

        success:
          true,

        message:
          "Respaldo creado correctamente.",

        backup: {

          nombre:
            backup.nombre,

          tamaño:
            backup.tamaño,

          tamaño_mb:
            Number(
              (
                backup.tamaño /
                1024 /
                1024
              ).toFixed(
                2
              )
            ),

          fecha:
            backup.fecha,

          origen:
            backup.origen

        },

        limpieza

      });

  }

  catch (
    error
  ) {

    console.error(
      "❌ Error creando respaldo manual:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          error.message ||
          "No se pudo crear el respaldo."

      });

  }

}


// ==================================================
// DESCARGAR RESPALDO
// GET /api/backups/:nombre/download
// ==================================================

export async function descargarBackup(
  req,
  res
) {

  try {

    if (
      !validarMaster(
        req,
        res
      )
    ) {

      return;

    }


    const nombre =
      req.params.nombre;


    const ruta =
      obtenerRutaBackup(
        nombre
      );


    if (
      !ruta
    ) {

      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "El respaldo no existe."

        });

    }


    return res.download(
      ruta,
      nombre
    );

  }

  catch (
    error
  ) {

    console.error(
      "❌ Error descargando respaldo:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "No se pudo descargar el respaldo."

      });

  }

}


// ==================================================
// INFORMACIÓN DEL SISTEMA DE RESPALDOS
// GET /api/backups/status
// ==================================================

export async function estadoBackups(
  req,
  res
) {

  try {

    if (
      !validarMaster(
        req,
        res
      )
    ) {

      return;

    }


    const backups =
      listarBackups();


    const ultimo =
      backups.length >
      0
        ? backups[0]
        : null;


    return res.json({

      success:
        true,

      sistema:
        "activo",

      automatico:
        true,

      frecuencia:
        "diario",

      hora:
        Number(
          process.env
            .BACKUP_HOUR ||
          2
        ),

      dias_retencion:
        backupConfig
          .diasRetencion,

      total_respaldos:
        backups.length,

      ultimo_respaldo:
        ultimo

    });

  }

  catch (
    error
  ) {

    console.error(
      "❌ Error obteniendo estado de respaldos:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "No se pudo consultar el sistema de respaldos."

      });

  }

}