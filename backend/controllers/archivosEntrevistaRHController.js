// ==================================================
// backend/controllers/archivosEntrevistaRHController.js
// ==================================================

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


// ==================================================
// VALIDAR ACCESO A ENTREVISTA RH
// ==================================================

const validarAccesoEntrevistaRH =
  async (
    idProspecto,
    idEntrevista,
    user
  ) => {

    const idUsuario =
      user?.id_usuario;

    const tipoAdmin =
      user?.tipo_admin
        ? String(user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;

    const area =
      user?.area
        ? String(user.area)
            .trim()
            .toLowerCase()
        : null;


    if (!idUsuario) {

      return {
        ok: false,
        status: 401,
        message:
          "No se pudo identificar al usuario"
      };

    }


    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "No tienes permiso para acceder a archivos de entrevistas RH"
      };

    }


    let query = `
      SELECT
        ep.id_entrevista,
        ep.id_prospecto,
        ep.modalidad,
        ep.enlace_videollamada,
        ep.grabacion_url,
        ep.transcripcion,
        ep.estatus,

        p.id_mirror,
        p.nombre,
        p.id_admin_padre

      FROM entrevistas_prospectos ep

      INNER JOIN prospectos p
        ON p.id_prospecto =
           ep.id_prospecto

      WHERE ep.id_prospecto = ?
        AND ep.id_entrevista = ?
    `;


    const params = [
      idProspecto,
      idEntrevista
    ];


    if (
      tipoAdmin !== "master"
    ) {

      query += `
        AND p.id_admin_padre = ?
      `;

      params.push(
        idUsuario
      );

    }


    query += `
      LIMIT 1
    `;


    const [rows] =
      await pool.query(
        query,
        params
      );


    if (!rows.length) {

      return {
        ok: false,
        status: 404,
        message:
          "Entrevista no encontrada o no tienes permiso para acceder a ella"
      };

    }


    return {
      ok: true,
      entrevista:
        rows[0]
    };

  };


// ==================================================
// SUBIR GRABACIÓN RH
//
// POST
// /api/archivos-rh/prospecto/:idProspecto/entrevista/:idEntrevista
// ==================================================

export async function subirArchivoEntrevistaRH(
  req,
  res
) {

  try {

    const idProspecto =
      Number(
        req.params.idProspecto
      );

    const idEntrevista =
      Number(
        req.params.idEntrevista
      );


    if (
      !Number.isInteger(idProspecto) ||
      idProspecto <= 0 ||
      !Number.isInteger(idEntrevista) ||
      idEntrevista <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Identificador de prospecto o entrevista inválido"
      });

    }


    const acceso =
      await validarAccesoEntrevistaRH(
        idProspecto,
        idEntrevista,
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({
          success: false,
          message:
            acceso.message
        });

    }


    if (!req.file) {

      return res.status(400).json({
        success: false,
        message:
          "No se recibió archivo"
      });

    }


    const {
      tipo,
      descripcion,
      duracion
    } = req.body;


    const ruta =
      "/uploads/multimedia/" +
      req.file.filename;


    const formato =
      req.file.mimetype;


    const tipoFinal =
      tipo === "audio"
        ? "audio"
        : "video";


    const [result] =
      await pool.query(
        `
          INSERT INTO videos_entrevista_rh
          (
            id_prospecto,
            id_entrevista,
            id_usuario_registro,

            ruta_video,
            tipo,
            descripcion,
            duracion_segundos,
            formato,

            transcripcion_estado,
            fecha_subida
          )

          VALUES
          (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            'pendiente',
            NOW()
          )
        `,
        [
          idProspecto,

          idEntrevista,

          req.user?.id_usuario ||
            null,

          ruta,

          tipoFinal,

          descripcion ||
            "Grabación de entrevista RH",

          duracion ||
            null,

          formato
        ]
      );


    // ==================================================
    // GUARDAR GRABACIÓN PRINCIPAL EN ENTREVISTA
    //
    // EntrevistasProspecto ya sabe mostrar este campo.
    // ==================================================

    await pool.query(
      `
        UPDATE entrevistas_prospectos

        SET
          grabacion_url = ?,
          actualizado_en = NOW()

        WHERE id_entrevista = ?
          AND id_prospecto = ?
      `,
      [
        ruta,
        idEntrevista,
        idProspecto
      ]
    );


    return res.status(201).json({

      success:
        true,

      message:
        "✅ Grabación RH guardada correctamente",

      id_video:
        result.insertId,

      id_video_rh:
        result.insertId,

      id_prospecto:
        idProspecto,

      id_entrevista:
        idEntrevista,

      ruta,

      grabacion_url:
        ruta,

      tipo:
        tipoFinal,

      formato

    });


  } catch (err) {

    console.error(
      "❌ Error al subir grabación RH:",
      err
    );


    return res.status(500).json({

      success:
        false,

      message:
        "Error al subir la grabación de la entrevista RH",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined

    });

  }

}


// ==================================================
// OBTENER GRABACIONES DE ENTREVISTA
//
// GET
// /api/archivos-rh/prospecto/:idProspecto/entrevista/:idEntrevista
// ==================================================

export async function obtenerArchivosEntrevistaRH(
  req,
  res
) {

  try {

    const idProspecto =
      Number(
        req.params.idProspecto
      );

    const idEntrevista =
      Number(
        req.params.idEntrevista
      );


    if (
      !Number.isInteger(idProspecto) ||
      idProspecto <= 0 ||
      !Number.isInteger(idEntrevista) ||
      idEntrevista <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Identificador inválido"
      });

    }


    const acceso =
      await validarAccesoEntrevistaRH(
        idProspecto,
        idEntrevista,
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({
          success: false,
          message:
            acceso.message
        });

    }


    const [rows] =
      await pool.query(
        `
          SELECT
            id_video_rh,
            id_prospecto,
            id_entrevista,
            id_usuario_registro,

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

          FROM videos_entrevista_rh

          WHERE id_prospecto = ?
            AND id_entrevista = ?

          ORDER BY
            fecha_subida DESC,
            id_video_rh DESC
        `,
        [
          idProspecto,
          idEntrevista
        ]
      );


    return res.json({

      success:
        true,

      prospecto: {

        id_prospecto:
          idProspecto,

        nombre:
          acceso.entrevista.nombre,

        id_mirror:
          acceso.entrevista.id_mirror

      },

      entrevista:
        acceso.entrevista,

      archivos:
        rows || []

    });


  } catch (err) {

    console.error(
      "❌ Error al obtener grabaciones RH:",
      err
    );


    return res.status(500).json({

      success:
        false,

      message:
        "Error al obtener las grabaciones de la entrevista RH",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined

    });

  }

}


// ==================================================
// TRANSCRIBIR GRABACIÓN RH
//
// POST
// /api/archivos-rh/:id/transcribir
// ==================================================

export async function transcribirArchivoEntrevistaRH(
  req,
  res
) {

  const idVideo =
    Number(
      req.params.id
    );


  if (
    !Number.isInteger(idVideo) ||
    idVideo <= 0
  ) {

    return res.status(400).json({
      success: false,
      message:
        "ID de archivo inválido"
    });

  }


  try {

    // ==================================================
    // OBTENER ARCHIVO RH
    // ==================================================

    const [rows] =
      await pool.query(
        `
          SELECT
            id_video_rh,
            id_prospecto,
            id_entrevista,
            ruta_video,
            tipo,
            formato,
            transcripcion,
            transcripcion_estado

          FROM videos_entrevista_rh

          WHERE id_video_rh = ?

          LIMIT 1
        `,
        [
          idVideo
        ]
      );


    if (!rows.length) {

      return res.status(404).json({
        success: false,
        message:
          "Grabación RH no encontrada"
      });

    }


    const archivo =
      rows[0];


    // ==================================================
    // VALIDAR ACCESO
    // ==================================================

    const acceso =
      await validarAccesoEntrevistaRH(
        archivo.id_prospecto,
        archivo.id_entrevista,
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({
          success: false,
          message:
            acceso.message
        });

    }


    // ==================================================
    // VALIDAR TIPO
    // ==================================================

    const esAudio =
      archivo.tipo === "audio" ||
      String(
        archivo.formato ||
        ""
      ).startsWith(
        "audio/"
      );


    const esVideo =
      archivo.tipo === "video" ||
      String(
        archivo.formato ||
        ""
      ).startsWith(
        "video/"
      );


    if (
      !esAudio &&
      !esVideo
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Este archivo no es una grabación de audio o video"
      });

    }


    // ==================================================
    // YA TRANSCRITO
    // ==================================================

    if (
      archivo.transcripcion &&
      String(
        archivo.transcripcion
      ).trim()
    ) {

      return res.json({

        success:
          true,

        ya_existia:
          true,

        id_video:
          archivo.id_video_rh,

        id_video_rh:
          archivo.id_video_rh,

        id_prospecto:
          archivo.id_prospecto,

        id_entrevista:
          archivo.id_entrevista,

        transcripcion:
          archivo.transcripcion

      });

    }


    // ==================================================
    // MARCAR PROCESANDO
    // ==================================================

    await pool.query(
      `
        UPDATE videos_entrevista_rh

        SET transcripcion_estado =
          'procesando'

        WHERE id_video_rh = ?
      `,
      [
        idVideo
      ]
    );


    // ==================================================
    // RUTA FÍSICA
    // ==================================================

    const rutaRelativa =
      String(
        archivo.ruta_video ||
        ""
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
      "🎙️ Grabación RH a transcribir:",
      rutaFisica
    );


    // ==================================================
    // TRANSCRIBIR
    // ==================================================

    let resultado;


    if (esAudio) {

      resultado =
        await transcribirAudio(
          rutaFisica
        );

    } else {

      const mimeType =
        archivo.formato ||
        "video/webm";


      resultado =
        await transcribirMultimedia(
          rutaFisica,
          mimeType
        );

    }


    if (
      !resultado?.texto
    ) {

      throw new Error(
        "El servicio de transcripción no devolvió texto"
      );

    }


    // ==================================================
    // GUARDAR EN ARCHIVO RH
    // ==================================================

    await pool.query(
      `
        UPDATE videos_entrevista_rh

        SET
          transcripcion = ?,
          transcripcion_estado =
            'completada',
          transcripcion_fecha =
            NOW(),
          transcripcion_modelo = ?

        WHERE id_video_rh = ?
      `,
      [
        resultado.texto,

        resultado.modelo ||
          null,

        idVideo
      ]
    );


    // ==================================================
    // GUARDAR TAMBIÉN EN LA ENTREVISTA
    //
    // Así aparece directamente en
    // EntrevistasProspecto.
    // ==================================================

    await pool.query(
      `
        UPDATE entrevistas_prospectos

        SET
          transcripcion = ?,
          actualizado_en = NOW()

        WHERE id_entrevista = ?
          AND id_prospecto = ?
      `,
      [
        resultado.texto,

        archivo.id_entrevista,

        archivo.id_prospecto
      ]
    );


    return res.json({

      success:
        true,

      message:
        esAudio
          ? "✅ Audio RH transcrito correctamente"
          : "✅ Videollamada RH transcrita correctamente",

      id_video:
        archivo.id_video_rh,

      id_video_rh:
        archivo.id_video_rh,

      id_prospecto:
        archivo.id_prospecto,

      id_entrevista:
        archivo.id_entrevista,

      tipo:
        archivo.tipo,

      formato:
        archivo.formato,

      transcripcion:
        resultado.texto,

      modelo:
        resultado.modelo ||
        null

    });


  } catch (err) {

    console.error(
      "❌ Error al transcribir grabación RH:",
      err
    );


    try {

      await pool.query(
        `
          UPDATE videos_entrevista_rh

          SET transcripcion_estado =
            'error'

          WHERE id_video_rh = ?
        `,
        [
          idVideo
        ]
      );

    } catch {}


    return res.status(500).json({

      success:
        false,

      message:
        "Error al transcribir la grabación RH",

      error:
        err.message

    });

  }

}


// ==================================================
// ELIMINAR GRABACIÓN RH
//
// DELETE /api/archivos-rh/:id
// ==================================================

export async function eliminarArchivoEntrevistaRH(
  req,
  res
) {

  const idVideo =
    Number(
      req.params.id
    );


  if (
    !Number.isInteger(idVideo) ||
    idVideo <= 0
  ) {

    return res.status(400).json({
      success: false,
      message:
        "ID de archivo inválido"
    });

  }


  try {

    const [rows] =
      await pool.query(
        `
          SELECT
            id_video_rh,
            id_prospecto,
            id_entrevista,
            ruta_video

          FROM videos_entrevista_rh

          WHERE id_video_rh = ?

          LIMIT 1
        `,
        [
          idVideo
        ]
      );


    if (!rows.length) {

      return res.status(404).json({
        success: false,
        message:
          "Grabación RH no encontrada"
      });

    }


    const archivo =
      rows[0];


    const acceso =
      await validarAccesoEntrevistaRH(
        archivo.id_prospecto,
        archivo.id_entrevista,
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({
          success: false,
          message:
            acceso.message
        });

    }


    await pool.query(
      `
        DELETE FROM
          videos_entrevista_rh

        WHERE id_video_rh = ?
      `,
      [
        idVideo
      ]
    );


    // ==================================================
    // BUSCAR GRABACIÓN ANTERIOR
    // ==================================================

    const [restantes] =
      await pool.query(
        `
          SELECT
            ruta_video,
            transcripcion

          FROM videos_entrevista_rh

          WHERE id_entrevista = ?
            AND id_prospecto = ?

          ORDER BY
            fecha_subida DESC,
            id_video_rh DESC

          LIMIT 1
        `,
        [
          archivo.id_entrevista,
          archivo.id_prospecto
        ]
      );


    const siguiente =
      restantes[0] ||
      null;


    await pool.query(
      `
        UPDATE entrevistas_prospectos

        SET
          grabacion_url = ?,
          transcripcion = ?,
          actualizado_en = NOW()

        WHERE id_entrevista = ?
          AND id_prospecto = ?
      `,
      [
        siguiente?.ruta_video ||
          null,

        siguiente?.transcripcion ||
          null,

        archivo.id_entrevista,

        archivo.id_prospecto
      ]
    );


    return res.json({
      success: true,
      message:
        "✅ Grabación RH eliminada correctamente"
    });


  } catch (err) {

    console.error(
      "❌ Error al eliminar grabación RH:",
      err
    );


    return res.status(500).json({

      success:
        false,

      message:
        "Error al eliminar la grabación RH",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined

    });

  }

}