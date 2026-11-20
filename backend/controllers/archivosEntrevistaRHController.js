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
// NORMALIZAR MIME DE GRABACIÓN
//
// Evita casos como:
// .webm -> text/plain
//
// Ejemplos correctos:
// video/webm
// audio/webm
// audio/ogg
// video/mp4
// ==================================================

const normalizarMimeGrabacion = ({
  mime = "",
  nombreArchivo = "",
  tipo = "video"
}) => {
  const tipoNormalizado =
    String(
      tipo || ""
    )
      .trim()
      .toLowerCase() === "audio"
      ? "audio"
      : "video";

  const mimeRecibido =
    String(
      mime || ""
    )
      .trim()
      .toLowerCase();

  const nombre =
    String(
      nombreArchivo || ""
    )
      .trim()
      .toLowerCase();

  // ==================================================
  // WEBM
  // ==================================================

  if (
    nombre.endsWith(".webm")
  ) {
    return tipoNormalizado ===
      "audio"
      ? "audio/webm"
      : "video/webm";
  }

  // ==================================================
  // OGG
  // ==================================================

  if (
    nombre.endsWith(".ogg")
  ) {
    return "audio/ogg";
  }

  // ==================================================
  // MP4
  // ==================================================

  if (
    nombre.endsWith(".mp4")
  ) {
    return tipoNormalizado ===
      "audio"
      ? "audio/mp4"
      : "video/mp4";
  }

  // ==================================================
  // MIME INVÁLIDO / GENÉRICO
  // ==================================================

  if (
    !mimeRecibido ||
    mimeRecibido ===
      "text/plain" ||
    mimeRecibido ===
      "application/octet-stream"
  ) {
    return tipoNormalizado ===
      "audio"
      ? "audio/webm"
      : "video/webm";
  }

  // ==================================================
  // MIME VÁLIDO RECIBIDO
  // ==================================================

  return mimeRecibido;
};

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
      Number(user?.id_usuario) || null;

    if (!idUsuario) {
      return {
        ok: false,
        status: 401,
        message:
          "No se pudo identificar al usuario"
      };
    }

    // ==================================================
    // CONTEXTO REAL DEL USUARIO RH
    // ==================================================

    const [usuarios] =
      await pool.query(
        `
          SELECT
            u.id_usuario,
            u.tipo_admin,
            u.area,
            u.rol,
            u.id_admin_padre,
            u.id_organizacion,
            o.tipo AS tipo_organizacion,
            o.perfil_independiente,
            o.estado AS estado_organizacion
          FROM usuarios u
          LEFT JOIN organizaciones o
            ON o.id_organizacion =
               u.id_organizacion
          WHERE u.id_usuario = ?
          LIMIT 1
        `,
        [
          idUsuario
        ]
      );

    if (!usuarios.length) {
      return {
        ok: false,
        status: 401,
        message:
          "No se pudo identificar al usuario"
      };
    }

    const usuario =
      usuarios[0];

    const tipoAdmin =
      String(
        usuario.tipo_admin || ""
      )
        .trim()
        .toLowerCase();

    const area =
      String(
        usuario.area || ""
      )
        .trim()
        .toLowerCase();

    const rol =
      String(
        usuario.rol || ""
      )
        .trim()
        .toLowerCase();

    const perfilIndependiente =
      String(
        usuario.perfil_independiente ||
        ""
      )
        .trim()
        .toLowerCase();

    const estadoOrganizacion =
      String(
        usuario.estado_organizacion ||
        ""
      )
        .trim()
        .toLowerCase();

    const esMaster =
      tipoAdmin === "master";

    const esAdminRH =
      tipoAdmin === "normal" &&
      area === "rh";

    const esUsuarioRH =
      rol === "rh" &&
      area === "rh";

    const esIndependienteRH =
      rol === "independiente" &&
      area === "independiente" &&
      perfilIndependiente === "rh" &&
      estadoOrganizacion === "activa";

    const tienePermiso =
      esMaster ||
      esAdminRH ||
      esUsuarioRH ||
      esIndependienteRH;

    if (!tienePermiso) {
      return {
        ok: false,
        status: 403,
        message:
          "No tienes permiso para acceder a archivos de entrevistas RH"
      };
    }

    // ==================================================
    // VALIDAR ENTREVISTA Y PROPIEDAD DEL PROSPECTO
    // ==================================================

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

    if (!esMaster) {
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
        rows[0],

      contexto: {
        idUsuario,
        tipoAdmin,
        area,
        rol,

        idOrganizacion:
          Number(
            usuario.id_organizacion
          ) || null,

        perfilIndependiente,

        esMaster,
        esAdminRH,
        esUsuarioRH,
        esIndependienteRH
      }
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

    // ==================================================
    // VALIDAR IDS
    // ==================================================

    if (
      !Number.isInteger(
        idProspecto
      ) ||
      idProspecto <= 0 ||
      !Number.isInteger(
        idEntrevista
      ) ||
      idEntrevista <= 0
    ) {
      return res
        .status(400)
        .json({
          success: false,

          message:
            "Identificador de prospecto o entrevista inválido"
        });
    }

    // ==================================================
    // VALIDAR ACCESO
    // ==================================================

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

    // ==================================================
    // VALIDAR ARCHIVO
    // ==================================================

    if (!req.file) {
      return res
        .status(400)
        .json({
          success: false,

          message:
            "No se recibió archivo"
        });
    }

    // ==================================================
    // DATOS
    // ==================================================

    const {
      tipo,
      descripcion,
      duracion
    } = req.body;

    const tipoFinal =
      String(
        tipo || ""
      )
        .trim()
        .toLowerCase() ===
      "audio"
        ? "audio"
        : "video";

    const ruta =
      "/uploads/multimedia/" +
      req.file.filename;

    // ==================================================
    // NORMALIZAR MIME
    // ==================================================

    const formato =
      normalizarMimeGrabacion({
        mime:
          req.file?.mimetype,

        nombreArchivo:
          req.file?.filename ||
          req.file?.originalname,

        tipo:
          tipoFinal
      });

    console.log(
      "📦 MIME RH normalizado:",
      {
        recibido:
          req.file?.mimetype,

        guardado:
          formato,

        tipo:
          tipoFinal,

        archivo:
          req.file?.filename
      }
    );

    // ==================================================
    // DURACIÓN
    // ==================================================

    const duracionNumero =
      Number(
        duracion
      );

    const duracionFinal =
      Number.isFinite(
        duracionNumero
      ) &&
      duracionNumero > 0
        ? Math.round(
            duracionNumero
          )
        : null;

    console.log(
      "⏱️ Duración RH recibida:",
      {
        original:
          duracion,

        guardada:
          duracionFinal
      }
    );

    // ==================================================
    // INSERTAR GRABACIÓN
    // ==================================================

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

          duracionFinal,

          formato
        ]
      );

    // ==================================================
    // GUARDAR GRABACIÓN PRINCIPAL EN ENTREVISTA
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

    console.log(
      "✅ Grabación RH guardada:",
      {
        id_video_rh:
          result.insertId,

        tipo:
          tipoFinal,

        formato,

        duracion:
          duracionFinal,

        ruta
      }
    );

    // ==================================================
    // RESPUESTA
    // ==================================================

    return res
      .status(201)
      .json({
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

        formato,

        duracion:
          duracionFinal,

        duracion_segundos:
          duracionFinal,

        transcripcion_estado:
          "pendiente"
      });
  } catch (err) {
    console.error(
      "❌ Error al subir grabación RH:",
      err
    );

    return res
      .status(500)
      .json({
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

    // ==================================================
    // VALIDAR IDS
    // ==================================================

    if (
      !Number.isInteger(
        idProspecto
      ) ||
      idProspecto <= 0 ||
      !Number.isInteger(
        idEntrevista
      ) ||
      idEntrevista <= 0
    ) {
      return res
        .status(400)
        .json({
          success: false,

          message:
            "Identificador inválido"
        });
    }

    // ==================================================
    // VALIDAR ACCESO
    // ==================================================

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

    // ==================================================
    // OBTENER ARCHIVOS
    // ==================================================

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

    return res
      .status(500)
      .json({
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
    !Number.isInteger(
      idVideo
    ) ||
    idVideo <= 0
  ) {
    return res
      .status(400)
      .json({
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
      return res
        .status(404)
        .json({
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
    // NORMALIZAR TIPO
    // ==================================================

    const tipoArchivo =
      String(
        archivo.tipo ||
        ""
      )
        .trim()
        .toLowerCase();

    const esAudio =
      tipoArchivo ===
        "audio" ||
      (
        tipoArchivo !==
          "video" &&
        String(
          archivo.formato ||
          ""
        )
          .toLowerCase()
          .startsWith(
            "audio/"
          )
      );

    const esVideo =
      tipoArchivo ===
        "video" ||
      (
        tipoArchivo !==
          "audio" &&
        String(
          archivo.formato ||
          ""
        )
          .toLowerCase()
          .startsWith(
            "video/"
          )
      );

    if (
      !esAudio &&
      !esVideo
    ) {
      return res
        .status(400)
        .json({
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

    if (!rutaRelativa) {
      throw new Error(
        "La grabación RH no tiene una ruta de archivo válida"
      );
    }

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
    // NORMALIZAR MIME TAMBIÉN AL TRANSCRIBIR
    // ==================================================

    const mimeType =
      normalizarMimeGrabacion({
        mime:
          archivo.formato,

        nombreArchivo:
          archivo.ruta_video,

        tipo:
          esAudio
            ? "audio"
            : "video"
      });

    console.log(
      "📦 MIME RH preparado para IA:",
      {
        original:
          archivo.formato,

        normalizado:
          mimeType,

        tipo:
          archivo.tipo,

        archivo:
          archivo.ruta_video
      }
    );

    // ==================================================
    // ACTUALIZAR FORMATO SI ESTABA MAL
    // ==================================================

    if (
      mimeType !==
      String(
        archivo.formato ||
        ""
      )
        .trim()
        .toLowerCase()
    ) {
      await pool.query(
        `
          UPDATE videos_entrevista_rh

          SET formato = ?

          WHERE id_video_rh = ?
        `,
        [
          mimeType,
          idVideo
        ]
      );

      console.log(
        "🔧 MIME RH corregido en BD:",
        {
          id_video_rh:
            idVideo,

          anterior:
            archivo.formato,

          nuevo:
            mimeType
        }
      );
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
    // TRANSCRIBIR
    // ==================================================

    let resultado;

    if (esAudio) {
      console.log(
        "🎙️ Enviando audio RH a transcripción..."
      );

      resultado =
        await transcribirAudio(
          rutaFisica
        );
    } else {
      console.log(
        "🎥 Enviando videollamada RH a transcripción...",
        {
          mimeType
        }
      );

      resultado =
        await transcribirMultimedia(
          rutaFisica,
          mimeType
        );
    }

    // ==================================================
    // VALIDAR RESPUESTA
    // ==================================================

    if (
      !resultado?.texto
    ) {
      throw new Error(
        "El servicio de transcripción no devolvió texto"
      );
    }

    const transcripcion =
      String(
        resultado.texto
      ).trim();

    if (!transcripcion) {
      throw new Error(
        "La transcripción recibida está vacía"
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
          transcripcion_modelo = ?,
          formato = ?

        WHERE id_video_rh = ?
      `,
      [
        transcripcion,

        resultado.modelo ||
          null,

        mimeType,

        idVideo
      ]
    );

    // ==================================================
    // GUARDAR TAMBIÉN EN LA ENTREVISTA
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
        transcripcion,

        archivo.id_entrevista,

        archivo.id_prospecto
      ]
    );

    console.log(
      "✅ Transcripción RH completada:",
      {
        id_video_rh:
          idVideo,

        caracteres:
          transcripcion.length,

        modelo:
          resultado.modelo ||
          null,

        formato:
          mimeType
      }
    );

    // ==================================================
    // RESPUESTA
    // ==================================================

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
        mimeType,

      transcripcion,

      modelo:
        resultado.modelo ||
        null
    });
  } catch (err) {
    console.error(
      "❌ Error al transcribir grabación RH:",
      err
    );

    // ==================================================
    // MARCAR ERROR
    // ==================================================

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
    } catch (
      errorActualizandoEstado
    ) {
      console.error(
        "❌ No se pudo marcar transcripción RH como error:",
        errorActualizandoEstado
      );
    }

    // ==================================================
    // GEMINI 429
    // ==================================================

    const esLimiteIA =
      Number(
        err?.status
      ) === 429 ||
      String(
        err?.message ||
        ""
      ).includes(
        "429"
      ) ||
      String(
        err?.message ||
        ""
      )
        .toLowerCase()
        .includes(
          "quota"
        );

    if (esLimiteIA) {
      return res
        .status(429)
        .json({
          success:
            false,

          code:
            "AI_QUOTA_LIMIT",

          message:
            "El servicio de IA alcanzó temporalmente su límite de uso. La grabación quedó guardada correctamente y podrás intentar transcribirla nuevamente.",

          id_video_rh:
            idVideo,

          error:
            process.env.NODE_ENV ===
            "development"
              ? err.message
              : undefined
        });
    }

    return res
      .status(500)
      .json({
        success:
          false,

        message:
          "Error al transcribir la grabación RH",

        id_video_rh:
          idVideo,

        error:
          process.env.NODE_ENV ===
          "development"
            ? err.message
            : undefined
      });
  }
}

// ==================================================
// ELIMINAR GRABACIÓN RH
//
// DELETE
// /api/archivos-rh/:id
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
    !Number.isInteger(
      idVideo
    ) ||
    idVideo <= 0
  ) {
    return res
      .status(400)
      .json({
        success: false,

        message:
          "ID de archivo inválido"
      });
  }

  try {
    // ==================================================
    // OBTENER ARCHIVO
    // ==================================================

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
      return res
        .status(404)
        .json({
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
    // ELIMINAR REGISTRO
    // ==================================================

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

    // ==================================================
    // ACTUALIZAR ENTREVISTA
    // ==================================================

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
      success:
        true,

      message:
        "✅ Grabación RH eliminada correctamente"
    });
  } catch (err) {
    console.error(
      "❌ Error al eliminar grabación RH:",
      err
    );

    return res
      .status(500)
      .json({
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