import pool from "../config/database.js";

import {
  transcribirAudio,
  transcribirMultimedia
} from "../svc/aiService.js";

import path from "path";
import { fileURLToPath } from "url";

const __filename =
  fileURLToPath(import.meta.url);

const __dirname =
  path.dirname(__filename);


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


    if (!id_sesion) {

      return res.status(400).json({
        message:
          "Falta id_sesion"
      });

    }


    if (!req.file) {

      return res.status(400).json({
        message:
          "No se recibió archivo"
      });

    }


    const [sesion] =
      await pool.query(
        `SELECT id_sesion
         FROM sesiones
         WHERE id_sesion = ?`,
        [id_sesion]
      );


    if (!sesion.length) {

      return res.status(400).json({
        message:
          `Sesión ${id_sesion} no existe`
      });

    }


    const ruta =
      "/uploads/multimedia/" +
      req.file.filename;


    const formato =
      req.file.mimetype;


    const [result] =
      await pool.query(
        `INSERT INTO videos_sesion
         (
           id_sesion,
           ruta_video,
           tipo,
           descripcion,
           duracion_segundos,
           formato,
           fecha_subida
         )
         VALUES (?, ?, ?, ?, ?, ?, NOW())`,
        [
          id_sesion,
          ruta,
          tipo || "video",
          descripcion ||
            "Grabación de sesión",
          duracion || null,
          formato
        ]
      );


    res.status(201).json({

      message:
        "✅ Archivo multimedia guardado",

      id_video:
        result.insertId,

      ruta,

      tipo:
        tipo || "video",

      formato

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
   TRANSCRIBIR ARCHIVO

   POST /api/archivos/:id/transcribir

   SOPORTA:
   - audio/webm  → presencial
   - video/webm  → videollamada
================================================== */
export async function transcribirArchivo(
  req,
  res
) {

  const { id } = req.params;


  try {

    if (!id) {

      return res.status(400).json({
        message:
          "Falta el ID del archivo"
      });

    }


    /* ==========================================
       OBTENER ARCHIVO
    ========================================== */

    const [rows] =
      await pool.query(
        `SELECT
           id_video,
           id_sesion,
           ruta_video,
           tipo,
           formato,
           transcripcion,
           transcripcion_estado
         FROM videos_sesion
         WHERE id_video = ?
         LIMIT 1`,
        [id]
      );


    if (!rows.length) {

      return res.status(404).json({
        message:
          "Archivo multimedia no encontrado"
      });

    }


    const archivo =
      rows[0];


    /* ==========================================
       VALIDAR TIPO
    ========================================== */

    const esAudio =
      archivo.tipo === "audio" ||
      String(
        archivo.formato || ""
      ).startsWith(
        "audio/"
      );


    const esVideo =
      archivo.tipo === "video" ||
      String(
        archivo.formato || ""
      ).startsWith(
        "video/"
      );


    if (!esAudio && !esVideo) {

      return res.status(400).json({
        message:
          "Este archivo no es una grabación de audio o video."
      });

    }


    /* ==========================================
       SI YA EXISTE TRANSCRIPCIÓN
    ========================================== */

    if (
      archivo.transcripcion &&
      archivo.transcripcion.trim()
    ) {

      return res.json({

        success:
          true,

        ya_existia:
          true,

        id_video:
          archivo.id_video,

        id_sesion:
          archivo.id_sesion,

        tipo:
          archivo.tipo,

        formato:
          archivo.formato,

        transcripcion:
          archivo.transcripcion

      });

    }


    /* ==========================================
       MARCAR PROCESANDO
    ========================================== */

    await pool.query(
      `UPDATE videos_sesion
       SET transcripcion_estado = 'procesando'
       WHERE id_video = ?`,
      [id]
    );


    /* ==========================================
       CONSTRUIR RUTA FÍSICA
    ========================================== */

    const rutaRelativa =
      String(
        archivo.ruta_video || ""
      ).replace(
        /^\/+/,
        ""
      );


    const rutaFisica =
      path.resolve(
        __dirname,
        "..",
        rutaRelativa
      );


    console.log(
      "🎙️ Archivo a transcribir:",
      rutaFisica
    );


    console.log(
      "📦 Tipo:",
      archivo.tipo,
      "| MIME:",
      archivo.formato
    );


    /* ==========================================
       TRANSCRIBIR
    ========================================== */

    let resultado;


    if (esAudio) {

      console.log(
        "🎙️ Transcripción presencial"
      );


      resultado =
        await transcribirAudio(
          rutaFisica
        );


    } else {

      console.log(
        "🎥 Transcripción de videollamada"
      );


      const mimeType =
        archivo.formato ||
        "video/webm";


      resultado =
        await transcribirMultimedia(
          rutaFisica,
          mimeType
        );

    }


    /* ==========================================
       GUARDAR TRANSCRIPCIÓN
    ========================================== */

    await pool.query(
      `UPDATE videos_sesion
       SET
         transcripcion = ?,
         transcripcion_estado = 'completada',
         transcripcion_fecha = NOW(),
         transcripcion_modelo = ?
       WHERE id_video = ?`,
      [
        resultado.texto,
        resultado.modelo,
        id
      ]
    );


    return res.json({

      success:
        true,

      message:
        esAudio
          ? "✅ Audio transcrito correctamente"
          : "✅ Videollamada transcrita correctamente",

      id_video:
        archivo.id_video,

      id_sesion:
        archivo.id_sesion,

      tipo:
        archivo.tipo,

      formato:
        archivo.formato,

      transcripcion:
        resultado.texto,

      modelo:
        resultado.modelo

    });


  } catch (err) {

    console.error(
      "❌ Error al transcribir archivo:",
      err.message
    );


    try {

      await pool.query(
        `UPDATE videos_sesion
         SET transcripcion_estado = 'error'
         WHERE id_video = ?`,
        [id]
      );

    } catch {}


    return res.status(500).json({

      success:
        false,

      message:
        "Error al transcribir la grabación",

      error:
        err.message

    });

  }

}



/* ==================================================
   OBTENER ARCHIVOS DE UNA SESIÓN
================================================== */
export async function obtenerArchivosSesion(
  req,
  res
) {

  const { id_sesion } =
    req.params;


  try {

    if (!id_sesion) {

      return res.status(400).json({
        message:
          "Falta id_sesion"
      });

    }


    const [rows] =
      await pool.query(
        `SELECT
           id_video,
           id_sesion,
           ruta_video,
           tipo,
           descripcion,
           duracion_segundos,
           formato,
           transcripcion,
           transcripcion_estado,
           transcripcion_fecha,
           transcripcion_modelo,
           fecha_subida
         FROM videos_sesion
         WHERE id_sesion = ?
         ORDER BY fecha_subida DESC`,
        [id_sesion]
      );


    res.json(
      rows || []
    );


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
export async function eliminarArchivo(
  req,
  res
) {

  const { id } =
    req.params;


  try {

    if (!id) {

      return res.status(400).json({
        message:
          "Falta el ID del archivo"
      });

    }


    const [rows] =
      await pool.query(
        `SELECT
           id_video,
           ruta_video
         FROM videos_sesion
         WHERE id_video = ?`,
        [id]
      );


    if (!rows.length) {

      return res.status(404).json({
        message:
          "Archivo no encontrado"
      });

    }


    await pool.query(
      `DELETE FROM videos_sesion
       WHERE id_video = ?`,
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