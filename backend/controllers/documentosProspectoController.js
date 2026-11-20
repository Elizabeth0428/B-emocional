// ==================================================
// backend/controllers/documentosProspectoController.js
// ==================================================

import pool from "../config/database.js";

import {
  documentosRHPath
} from "../config/multerDocumentosRH.js";

import fs from "fs";
import path from "path";

// ==================================================
// TIPOS DE DOCUMENTOS PERMITIDOS
// ==================================================

const TIPOS_DOCUMENTO = [
  "cv",
  "identificacion",
  "constancia",
  "certificado",
  "comprobante",
  "otro"
];

// ==================================================
// AUXILIAR - TEXTO
// ==================================================

const limpiarTexto = (valor) => {

  if (
    valor === undefined ||
    valor === null
  ) {
    return null;
  }

  const texto =
    String(valor).trim();

  return texto || null;
};

// ==================================================
// VALIDAR ACCESO AL PROSPECTO
// ==================================================

const validarAccesoProspecto = async (
  idProspecto,
  user
) => {

  const idUsuario =
    Number(user?.id_usuario) || null;

  if (!idUsuario) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };
  }

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
      [idUsuario]
    );

  if (!usuarios.length) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
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
      usuario.perfil_independiente || ""
    )
      .trim()
      .toLowerCase();

  const estadoOrganizacion =
    String(
      usuario.estado_organizacion || ""
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
        "No tienes permiso para acceder a documentos de prospectos",
    };
  }

  let query = `
    SELECT
      *
    FROM prospectos
    WHERE id_prospecto = ?
  `;

  const params = [
    idProspecto
  ];

  if (!esMaster) {
    query += `
      AND id_admin_padre = ?
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
        "Prospecto no encontrado o no tienes permiso para acceder a él",
    };
  }

  return {
    ok: true,
    prospecto:
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
      esIndependienteRH,
    },
  };
};

// ==================================================
// ELIMINAR ARCHIVO FÍSICO AUXILIAR
// ==================================================

const eliminarArchivoFisico = async (
  nombreArchivo
) => {

  if (!nombreArchivo) {
    return;
  }

  const ruta =
    path.join(
      documentosRHPath,
      path.basename(nombreArchivo)
    );

  try {

    await fs.promises.unlink(
      ruta
    );

  } catch (error) {

    if (
      error.code !== "ENOENT"
    ) {

      console.error(
        "⚠️ No se pudo eliminar archivo físico:",
        error
      );
    }
  }
};

// ==================================================
// SUBIR DOCUMENTO
//
// POST /api/prospectos/:id/documentos
// ==================================================

export const subirDocumentoProspecto = async (
  req,
  res
) => {

  try {

    const idProspecto =
      Number(req.params.id);

    if (
      !Number.isInteger(idProspecto) ||
      idProspecto <= 0
    ) {

      if (req.file) {
        await eliminarArchivoFisico(
          req.file.filename
        );
      }

      return res.status(400).json({
        success: false,
        message:
          "ID de prospecto inválido"
      });
    }

    const acceso =
      await validarAccesoProspecto(
        idProspecto,
        req.user
      );

    if (!acceso.ok) {

      if (req.file) {
        await eliminarArchivoFisico(
          req.file.filename
        );
      }

      return res
        .status(acceso.status)
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
          "Selecciona un archivo"
      });
    }

    const tipoDocumento =
      String(
        req.body.tipo_documento ||
        "otro"
      )
        .trim()
        .toLowerCase();

    if (
      !TIPOS_DOCUMENTO.includes(
        tipoDocumento
      )
    ) {

      await eliminarArchivoFisico(
        req.file.filename
      );

      return res.status(400).json({
        success: false,
        message:
          "Tipo de documento inválido"
      });
    }

    const descripcion =
      limpiarTexto(
        req.body.descripcion
      );

    const rutaInterna =
      path.join(
        "storage",
        "documentos-prospectos",
        req.file.filename
      )
        .replaceAll("\\", "/");

    const [resultado] =
      await pool.query(
        `
          INSERT INTO documentos_prospectos
          (
            id_prospecto,
            id_usuario_registro,
            tipo_documento,
            nombre_original,
            nombre_archivo,
            ruta_archivo,
            mime_type,
            descripcion,
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
            NOW()
          )
        `,
        [
          idProspecto,

          req.user?.id_usuario ||
            null,

          tipoDocumento,

          req.file.originalname,

          req.file.filename,

          rutaInterna,

          req.file.mimetype,

          descripcion
        ]
      );

    const [rows] =
      await pool.query(
        `
          SELECT
            id_documento,
            id_prospecto,
            id_usuario_registro,
            tipo_documento,
            nombre_original,
            nombre_archivo,
            mime_type,
            descripcion,
            fecha_subida
          FROM documentos_prospectos
          WHERE id_documento = ?
          LIMIT 1
        `,
        [
          resultado.insertId
        ]
      );

    return res.status(201).json({
      success: true,

      message:
        "Documento guardado correctamente",

      documento:
        rows[0] || null
    });

  } catch (error) {

    if (req.file) {

      await eliminarArchivoFisico(
        req.file.filename
      );
    }

    console.error(
      "❌ Error subiendo documento del prospecto:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "No fue posible guardar el documento",

      error:
        process.env.NODE_ENV ===
        "development"
          ? error.message
          : undefined
    });
  }
};

// ==================================================
// LISTAR DOCUMENTOS
//
// GET /api/prospectos/:id/documentos
// ==================================================

export const listarDocumentosProspecto = async (
  req,
  res
) => {

  try {

    const idProspecto =
      Number(req.params.id);

    if (
      !Number.isInteger(idProspecto) ||
      idProspecto <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "ID de prospecto inválido"
      });
    }

    const acceso =
      await validarAccesoProspecto(
        idProspecto,
        req.user
      );

    if (!acceso.ok) {

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const [documentos] =
      await pool.query(
        `
          SELECT
            id_documento,
            id_prospecto,
            id_usuario_registro,
            tipo_documento,
            nombre_original,
            nombre_archivo,
            mime_type,
            descripcion,
            fecha_subida
          FROM documentos_prospectos
          WHERE id_prospecto = ?
          ORDER BY fecha_subida DESC,
                   id_documento DESC
        `,
        [
          idProspecto
        ]
      );

    return res.json({
      success: true,

      prospecto:
        acceso.prospecto,

      documentos
    });

  } catch (error) {

    console.error(
      "❌ Error listando documentos del prospecto:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "No fue posible obtener los documentos",

      error:
        process.env.NODE_ENV ===
        "development"
          ? error.message
          : undefined
    });
  }
};

// ==================================================
// ABRIR / DESCARGAR DOCUMENTO
//
// GET
// /api/prospectos/:id/documentos/:idDocumento/archivo
// ==================================================

export const obtenerArchivoDocumentoProspecto = async (
  req,
  res
) => {

  try {

    const idProspecto =
      Number(req.params.id);

    const idDocumento =
      Number(req.params.idDocumento);

    if (
      !Number.isInteger(idProspecto) ||
      idProspecto <= 0 ||
      !Number.isInteger(idDocumento) ||
      idDocumento <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Identificador inválido"
      });
    }

    const acceso =
      await validarAccesoProspecto(
        idProspecto,
        req.user
      );

    if (!acceso.ok) {

      return res
        .status(acceso.status)
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
            id_documento,
            id_prospecto,
            nombre_original,
            nombre_archivo,
            mime_type
          FROM documentos_prospectos
          WHERE id_documento = ?
            AND id_prospecto = ?
          LIMIT 1
        `,
        [
          idDocumento,
          idProspecto
        ]
      );

    if (!rows.length) {

      return res.status(404).json({
        success: false,
        message:
          "Documento no encontrado"
      });
    }

    const documento =
      rows[0];

    const rutaFisica =
      path.join(
        documentosRHPath,
        path.basename(
          documento.nombre_archivo
        )
      );

    if (
      !fs.existsSync(
        rutaFisica
      )
    ) {

      return res.status(404).json({
        success: false,
        message:
          "El archivo físico no fue encontrado"
      });
    }

    res.setHeader(
      "Content-Type",

      documento.mime_type ||
      "application/octet-stream"
    );

    res.setHeader(
      "Content-Disposition",

      `inline; filename*=UTF-8''${encodeURIComponent(
        documento.nombre_original
      )}`
    );

    return res.sendFile(
      rutaFisica
    );

  } catch (error) {

    console.error(
      "❌ Error abriendo documento del prospecto:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "No fue posible abrir el documento",

      error:
        process.env.NODE_ENV ===
        "development"
          ? error.message
          : undefined
    });
  }
};

// ==================================================
// ELIMINAR DOCUMENTO
//
// DELETE
// /api/prospectos/:id/documentos/:idDocumento
// ==================================================

export const eliminarDocumentoProspecto = async (
  req,
  res
) => {

  try {

    const idProspecto =
      Number(req.params.id);

    const idDocumento =
      Number(req.params.idDocumento);

    if (
      !Number.isInteger(idProspecto) ||
      idProspecto <= 0 ||
      !Number.isInteger(idDocumento) ||
      idDocumento <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Identificador inválido"
      });
    }

    const acceso =
      await validarAccesoProspecto(
        idProspecto,
        req.user
      );

    if (!acceso.ok) {

      return res
        .status(acceso.status)
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
            id_documento,
            nombre_archivo,
            nombre_original
          FROM documentos_prospectos
          WHERE id_documento = ?
            AND id_prospecto = ?
          LIMIT 1
        `,
        [
          idDocumento,
          idProspecto
        ]
      );

    if (!rows.length) {

      return res.status(404).json({
        success: false,
        message:
          "Documento no encontrado"
      });
    }

    const documento =
      rows[0];

    await pool.query(
      `
        DELETE FROM documentos_prospectos
        WHERE id_documento = ?
          AND id_prospecto = ?
      `,
      [
        idDocumento,
        idProspecto
      ]
    );

    await eliminarArchivoFisico(
      documento.nombre_archivo
    );

    return res.json({
      success: true,

      message:
        "Documento eliminado correctamente"
    });

  } catch (error) {

    console.error(
      "❌ Error eliminando documento del prospecto:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "No fue posible eliminar el documento",

      error:
        process.env.NODE_ENV ===
        "development"
          ? error.message
          : undefined
    });
  }
};