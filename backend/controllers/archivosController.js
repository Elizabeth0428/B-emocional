// backend/controllers/archivosController.js

import pool from "../config/database.js";


/* ==================================================
   SUBIR ARCHIVO MULTIMEDIA DE UNA SESIÓN
================================================== */

export async function subirArchivo(req, res) {

  try {

    const {
      id_sesion,
      tipo,
      descripcion,
      duracion
    } = req.body;


    /* ==================================================
       VALIDACIONES
    ================================================== */

    if (!id_sesion) {
      return res.status(400).json({
        message: "Falta id_sesion"
      });
    }

    if (!req.file) {
      return res.status(400).json({
        message: "No se recibió archivo"
      });
    }


    /* ==================================================
       VALIDAR QUE LA SESIÓN EXISTA
    ================================================== */

    const [sesion] = await pool.query(
      `
      SELECT id_sesion
      FROM sesiones
      WHERE id_sesion = ?
      `,
      [id_sesion]
    );


    if (!sesion.length) {

      return res.status(400).json({
        message: `Sesión ${id_sesion} no existe`
      });

    }


    /* ==================================================
       DATOS DEL ARCHIVO
    ================================================== */

    const ruta =
      "/uploads/multimedia/" +
      req.file.filename;

    const formato =
      req.file.mimetype;


    /* ==================================================
       GUARDAR EN BASE DE DATOS
    ================================================== */

    const [result] = await pool.query(
      `
      INSERT INTO videos_sesion
      (
        id_sesion,
        ruta_video,
        tipo,
        descripcion,
        duracion_segundos,
        formato,
        fecha_subida
      )
      VALUES (?, ?, ?, ?, ?, ?, NOW())
      `,
      [
        id_sesion,
        ruta,
        tipo || "video",
        descripcion || "Grabación de sesión",
        duracion || null,
        formato
      ]
    );


    /* ==================================================
       RESPUESTA
    ================================================== */

    res.status(201).json({

      message:
        "✅ Archivo multimedia guardado",

      id_video:
        result.insertId,

      ruta,

      tipo:
        tipo || "video"

    });


  } catch (err) {

    console.error(
      "❌ Error al subir archivo:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al subir archivo multimedia"
    });

  }

}


/* ==================================================
   OBTENER ARCHIVOS DE UNA SESIÓN
================================================== */

export async function obtenerArchivosSesion(req, res) {

  const { id_sesion } = req.params;

  try {

    if (!id_sesion) {

      return res.status(400).json({
        message: "Falta id_sesion"
      });

    }


    const [rows] = await pool.query(
      `
      SELECT
        id_video,
        id_sesion,
        ruta_video,
        tipo,
        descripcion,
        duracion_segundos,
        formato,
        fecha_subida

      FROM videos_sesion

      WHERE id_sesion = ?

      ORDER BY fecha_subida DESC
      `,
      [id_sesion]
    );


    res.json(rows || []);


  } catch (err) {

    console.error(
      "❌ Error al obtener archivos:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al obtener archivos de la sesión"
    });

  }

}


/* ==================================================
   ELIMINAR ARCHIVO
================================================== */

export async function eliminarArchivo(req, res) {

  const { id } = req.params;

  try {

    if (!id) {

      return res.status(400).json({
        message: "Falta el ID del archivo"
      });

    }


    /* ==================================================
       VERIFICAR QUE EL ARCHIVO EXISTA
    ================================================== */

    const [rows] = await pool.query(
      `
      SELECT
        id_video,
        ruta_video

      FROM videos_sesion

      WHERE id_video = ?
      `,
      [id]
    );


    if (!rows.length) {

      return res.status(404).json({
        message: "Archivo no encontrado"
      });

    }


    /* ==================================================
       ELIMINAR REGISTRO DE BASE DE DATOS
    ================================================== */

    await pool.query(
      `
      DELETE FROM videos_sesion
      WHERE id_video = ?
      `,
      [id]
    );


    res.json({

      message:
        "✅ Archivo eliminado correctamente"

    });


  } catch (err) {

    console.error(
      "❌ Error al eliminar archivo:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al eliminar archivo"
    });

  }

}