// ==================================================
// backend/controllers/documentosEmpleadoController.js
// ==================================================

import pool from "../config/database.js";

import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// ==================================================
// __dirname
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
// CARPETA DE DOCUMENTOS DEL EMPLEADO
//
// backend/uploads/documentos-empleados
// ==================================================

const documentosEmpleadoPath =
  path.join(
    __dirname,
    "..",
    "uploads",
    "documentos-empleados"
  );

fs.mkdirSync(
  documentosEmpleadoPath,
  {
    recursive: true
  }
);

// ==================================================
// TIPOS ACEPTADOS POR LA INTERFAZ
// ==================================================

const TIPOS_DOCUMENTO = [
  "cv",
  "identificacion",
  "constancia",
  "certificado",
  "comprobante",
  "contrato",
  "otro"
];

// ==================================================
// MIME PERMITIDOS
// ==================================================

const MIME_PERMITIDOS = [
  "application/pdf",

  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",

  "application/msword",

  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
];

// ==================================================
// MULTER
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
          documentosEmpleadoPath
        );

      },

    filename:
      (
        req,
        file,
        cb
      ) => {

        const extension =
          path.extname(
            file.originalname ||
            ""
          );

        const nombre =
          `${Date.now()}-${Math.random()
            .toString(36)
            .substring(2, 10)}${extension}`;

        cb(
          null,
          nombre
        );

      }

  });

export const uploadDocumentoEmpleado =
  multer({

    storage,

    limits: {

      // 10 MB
      fileSize:
        10 * 1024 * 1024

    },

    fileFilter:
      (
        req,
        file,
        cb
      ) => {

        if (
          MIME_PERMITIDOS.includes(
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
            "Tipo de archivo no permitido. Usa PDF, JPG, PNG, WEBP, DOC o DOCX."
          )
        );

      }

  });

// ==================================================
// AUXILIAR: LIMPIAR TEXTO
// ==================================================

const limpiarTexto =
  valor => {

    if (
      valor === undefined ||
      valor === null
    ) {

      return null;

    }

    const texto =
      String(
        valor
      ).trim();

    return texto ||
      null;

  };

// ==================================================
// AUXILIAR: NORMALIZAR
// ==================================================

const normalizar =
  valor => {

    return valor
      ? String(
          valor
        )
          .trim()
          .toLowerCase()
      : "";

  };

// ==================================================
// AUXILIAR: ELIMINAR ARCHIVO FÍSICO
// ==================================================

const eliminarArchivoFisico =
  async nombreArchivo => {

    if (
      !nombreArchivo
    ) {

      return;

    }

    const ruta =
      path.join(
        documentosEmpleadoPath,
        path.basename(
          nombreArchivo
        )
      );

    try {

      await fs.promises.unlink(
        ruta
      );

    } catch (error) {

      if (
        error.code !==
        "ENOENT"
      ) {

        console.error(
          "⚠️ Error eliminando documento físico del empleado:",
          error
        );

      }

    }

  };

// ==================================================
// AUXILIAR: OBTENER CONTEXTO REAL DEL USUARIO
// ==================================================

const obtenerContextoUsuario =
  async (
    user,
    connection = pool
  ) => {

    const idUsuario =
      Number(
        user?.id_usuario
      ) || null;

    if (
      !idUsuario
    ) {

      return {

        idUsuario:
          null,

        tipoAdmin:
          "",

        area:
          "",

        rol:
          "",

        idAdminPadre:
          null,

        idOrganizacion:
          null,

        perfilIndependiente:
          "",

        estadoOrganizacion:
          ""

      };

    }

    const [rows] =
      await connection.query(
        `
          SELECT
            u.id_usuario,
            u.tipo_admin,
            u.area,
            u.rol,
            u.id_admin_padre,
            u.id_organizacion,

            o.perfil_independiente,
            o.estado AS estado_organizacion

          FROM usuarios u

          LEFT JOIN organizaciones o
            ON o.id_organizacion =
               u.id_organizacion

          WHERE
            u.id_usuario = ?

          LIMIT 1
        `,
        [
          idUsuario
        ]
      );

    if (
      !rows.length
    ) {

      return {

        idUsuario,

        tipoAdmin:
          normalizar(
            user?.tipo_admin
          ),

        area:
          normalizar(
            user?.area
          ),

        rol:
          normalizar(
            user?.rol
          ),

        idAdminPadre:
          Number(
            user?.id_admin_padre
          ) || null,

        idOrganizacion:
          Number(
            user?.id_organizacion
          ) || null,

        perfilIndependiente:
          normalizar(
            user?.perfil_independiente
          ),

        estadoOrganizacion:
          normalizar(
            user?.estado_organizacion
          )

      };

    }

    const usuario =
      rows[0];

    return {

      idUsuario:
        Number(
          usuario.id_usuario
        ) || null,

      tipoAdmin:
        normalizar(
          usuario.tipo_admin
        ),

      area:
        normalizar(
          usuario.area
        ),

      rol:
        normalizar(
          usuario.rol
        ),

      idAdminPadre:
        Number(
          usuario.id_admin_padre
        ) || null,

      idOrganizacion:
        Number(
          usuario.id_organizacion
        ) || null,

      perfilIndependiente:
        normalizar(
          usuario.perfil_independiente
        ),

      estadoOrganizacion:
        normalizar(
          usuario.estado_organizacion
        )

    };

  };

// ==================================================
// AUXILIAR: VALIDAR ACCESO AL EMPLEADO
//
// MASTER:
// - ve todos.
//
// ADMIN RH:
// - ve empleados de su administración.
// - también empleados antiguos registrados por sus RH.
//
// USUARIO RH:
// - ve empleados asignados actualmente a él.
// - también empleados antiguos donde
//   id_usuario_responsable = NULL
//   e id_admin_padre = su id_usuario.
//
// INDEPENDIENTE RH:
// - ve únicamente sus propios empleados.
// ==================================================

const validarAccesoEmpleado =
  async (
    idEmpleado,
    user,
    connection = pool
  ) => {

    const contexto =
      await obtenerContextoUsuario(
        user,
        connection
      );

    if (
      !contexto.idUsuario
    ) {

      return {

        ok: false,

        status: 401,

        message:
          "No se pudo identificar al usuario"

      };

    }

    // ==================================================
    // ROLES PERMITIDOS
    // ==================================================

    const esMaster =
      contexto.tipoAdmin ===
      "master";

    const esAdminRH =
      contexto.tipoAdmin ===
        "normal" &&
      contexto.area ===
        "rh";

    const esUsuarioRH =
      contexto.rol ===
        "rh" &&
      contexto.area ===
        "rh";

    const esIndependienteRH =
      contexto.rol ===
        "independiente" &&
      contexto.area ===
        "independiente" &&
      contexto.perfilIndependiente ===
        "rh" &&
      contexto.estadoOrganizacion ===
        "activa";

    if (
      !esMaster &&
      !esAdminRH &&
      !esUsuarioRH &&
      !esIndependienteRH
    ) {

      return {

        ok: false,

        status: 403,

        message:
          "No tienes permiso para acceder a documentos de empleados"

      };

    }

    // ==================================================
    // EMPLEADO
    // ==================================================

    let query = `
      SELECT
        e.id_empleado,
        e.id_prospecto,
        e.id_admin_padre,
        e.id_usuario_responsable,
        e.id_mirror,
        e.nombre,
        e.estatus

      FROM empleados e

      WHERE
        e.id_empleado = ?
    `;

    const params = [
      idEmpleado
    ];

    // ==================================================
    // ADMIN RH
    // ==================================================

    if (
      esAdminRH
    ) {

      query += `
        AND
        (
          e.id_admin_padre = ?

          OR

          (
            e.id_usuario_responsable IS NULL

            AND e.id_admin_padre IN
            (
              SELECT
                u.id_usuario

              FROM usuarios u

              WHERE
                u.id_admin_padre = ?

                AND u.rol = 'rh'

                AND LOWER(
                  TRIM(
                    COALESCE(
                      u.area,
                      ''
                    )
                  )
                ) = 'rh'
            )
          )
        )
      `;

      params.push(
        contexto.idUsuario,
        contexto.idUsuario
      );

    }

    // ==================================================
    // USUARIO RH / INDEPENDIENTE RH
    // ==================================================

    else if (
      esUsuarioRH ||
      esIndependienteRH
    ) {

      query += `
        AND
        (
          e.id_usuario_responsable = ?

          OR

          (
            e.id_usuario_responsable IS NULL

            AND e.id_admin_padre = ?
          )
        )
      `;

      params.push(
        contexto.idUsuario,
        contexto.idUsuario
      );

    }

    query += `
      LIMIT 1
    `;

    const [rows] =
      await connection.query(
        query,
        params
      );

    if (
      !rows.length
    ) {

      return {

        ok: false,

        status: 404,

        message:
          "Empleado no encontrado o no tienes permiso para acceder a él"

      };

    }

    return {

      ok: true,

      contexto: {
        ...contexto,

        esMaster,
        esAdminRH,
        esUsuarioRH,
        esIndependienteRH
      },

      empleado:
        rows[0]

    };

  };

// ==================================================
// AUXILIAR:
// VERIFICAR SI EL ENUM DE LA TABLA YA ACEPTA CONTRATO
//
// Si todavía no tiene 'contrato',
// lo guardamos como 'otro' para evitar que falle.
// ==================================================

const obtenerTipoDocumentoBD =
  async tipoSolicitado => {

    const tipo =
      String(
        tipoSolicitado ||
        "otro"
      )
        .trim()
        .toLowerCase();

    if (
      !TIPOS_DOCUMENTO.includes(
        tipo
      )
    ) {

      return {

        tipoBD:
          "otro",

        tipoOriginal:
          "otro"

      };

    }

    if (
      tipo !==
      "contrato"
    ) {

      return {

        tipoBD:
          tipo,

        tipoOriginal:
          tipo

      };

    }

    try {

      const [columnas] =
        await pool.query(
          `
            SHOW COLUMNS
            FROM documentos_empleados
            LIKE 'tipo_documento'
          `
        );

      const definicion =
        String(
          columnas?.[0]?.Type ||
          ""
        )
          .toLowerCase();

      if (
        definicion.includes(
          "'contrato'"
        )
      ) {

        return {

          tipoBD:
            "contrato",

          tipoOriginal:
            "contrato"

        };

      }

    } catch (error) {

      console.warn(
        "⚠️ No se pudo revisar enum tipo_documento:",
        error.message
      );

    }

    return {

      tipoBD:
        "otro",

      tipoOriginal:
        "contrato"

    };

  };

// ==================================================
// LISTAR DOCUMENTOS DEL EMPLEADO
//
// GET /api/empleados/:id/documentos
// ==================================================

export const listarDocumentosEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "ID de empleado inválido"

          });

      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (
        !acceso.ok
      ) {

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

      const [documentos] =
        await pool.query(
          `
            SELECT
              id_documento,
              id_empleado,
              tipo_documento,
              nombre_original,
              nombre_archivo,
              ruta_archivo,
              mime_type,
              descripcion,
              fecha_subida

            FROM documentos_empleados

            WHERE
              id_empleado = ?

            ORDER BY
              fecha_subida DESC,
              id_documento DESC
          `,
          [
            idEmpleado
          ]
        );

      return res.json({

        success: true,

        total:
          documentos.length,

        documentos

      });

    } catch (error) {

      console.error(
        "❌ Error listando documentos del empleado:",
        error
      );

      return res
        .status(500)
        .json({

          success: false,

          message:
            "Error interno al obtener los documentos del empleado",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined

        });

    }

  };

// ==================================================
// SUBIR DOCUMENTO DEL EMPLEADO
//
// POST /api/empleados/:id/documentos
//
// multipart/form-data
//
// file
// tipo_documento
// descripcion
// ==================================================

export const subirDocumentoEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );

      // ==================================================
      // VALIDAR ID
      // ==================================================

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {

        if (
          req.file
        ) {

          await eliminarArchivoFisico(
            req.file.filename
          );

        }

        return res
          .status(400)
          .json({

            success: false,

            message:
              "ID de empleado inválido"

          });

      }

      // ==================================================
      // VALIDAR ACCESO
      // ==================================================

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (
        !acceso.ok
      ) {

        if (
          req.file
        ) {

          await eliminarArchivoFisico(
            req.file.filename
          );

        }

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

      if (
        !req.file
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "Selecciona un archivo"

          });

      }

      // ==================================================
      // TIPO DOCUMENTO
      // ==================================================

      const tipoRecibido =
        String(
          req.body
            ?.tipo_documento ||
          "otro"
        )
          .trim()
          .toLowerCase();

      if (
        !TIPOS_DOCUMENTO.includes(
          tipoRecibido
        )
      ) {

        await eliminarArchivoFisico(
          req.file.filename
        );

        return res
          .status(400)
          .json({

            success: false,

            message:
              "Tipo de documento inválido"

          });

      }

      const {
        tipoBD,
        tipoOriginal
      } =
        await obtenerTipoDocumentoBD(
          tipoRecibido
        );

      // ==================================================
      // DESCRIPCIÓN
      // ==================================================

      let descripcion =
        limpiarTexto(
          req.body
            ?.descripcion
        );

      // Si la BD todavía no acepta "contrato"
      // conservamos esa información en descripción.

      if (
        tipoOriginal ===
          "contrato" &&
        tipoBD ===
          "otro"
      ) {

        descripcion =
          descripcion
            ? `Contrato laboral - ${descripcion}`
            : "Contrato laboral";

      }

      // ==================================================
      // RUTA PÚBLICA
      // ==================================================

      const rutaArchivo =
        `/uploads/documentos-empleados/${req.file.filename}`;

      // ==================================================
      // INSERTAR
      // ==================================================

      const [resultado] =
        await pool.query(
          `
            INSERT INTO documentos_empleados
            (
              id_empleado,
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
              NOW()
            )
          `,
          [
            idEmpleado,

            tipoBD,

            req.file
              .originalname,

            req.file
              .filename,

            rutaArchivo,

            req.file
              .mimetype ||
              null,

            descripcion
          ]
        );

      // ==================================================
      // DEVOLVER DOCUMENTO
      // ==================================================

      const [rows] =
        await pool.query(
          `
            SELECT
              id_documento,
              id_empleado,
              tipo_documento,
              nombre_original,
              nombre_archivo,
              ruta_archivo,
              mime_type,
              descripcion,
              fecha_subida

            FROM documentos_empleados

            WHERE
              id_documento = ?

            LIMIT 1
          `,
          [
            resultado.insertId
          ]
        );

      console.log(
        "✅ Documento empleado guardado:",
        {

          id_documento:
            resultado.insertId,

          id_empleado:
            idEmpleado,

          archivo:
            req.file.filename,

          tipo:
            tipoBD,

          mime:
            req.file.mimetype

        }
      );

      return res
        .status(201)
        .json({

          success: true,

          message:
            "Documento guardado correctamente",

          documento:
            rows[0] ||
            null

        });

    } catch (error) {

      if (
        req.file
      ) {

        await eliminarArchivoFisico(
          req.file.filename
        );

      }

      console.error(
        "❌ Error subiendo documento del empleado:",
        error
      );

      return res
        .status(500)
        .json({

          success: false,

          message:
            "Error interno al guardar el documento del empleado",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined

        });

    }

  };

// ==================================================
// ELIMINAR DOCUMENTO DEL EMPLEADO
//
// DELETE
// /api/empleados/:id/documentos/:idDocumento
// ==================================================

export const eliminarDocumentoEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );

      const idDocumento =
        Number(
          req.params
            .idDocumento
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "ID de empleado inválido"

          });

      }

      if (
        !Number.isInteger(
          idDocumento
        ) ||
        idDocumento <= 0
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "ID de documento inválido"

          });

      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (
        !acceso.ok
      ) {

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

      const [documentos] =
        await pool.query(
          `
            SELECT
              id_documento,
              id_empleado,
              nombre_archivo,
              ruta_archivo

            FROM documentos_empleados

            WHERE
              id_documento = ?

              AND id_empleado = ?

            LIMIT 1
          `,
          [
            idDocumento,
            idEmpleado
          ]
        );

      if (
        !documentos.length
      ) {

        return res
          .status(404)
          .json({

            success: false,

            message:
              "Documento no encontrado"

          });

      }

      const documento =
        documentos[0];

      await pool.query(
        `
          DELETE FROM
            documentos_empleados

          WHERE
            id_documento = ?

            AND id_empleado = ?
        `,
        [
          idDocumento,
          idEmpleado
        ]
      );

      // ==================================================
      // IMPORTANTE
      //
      // Algunos documentos vienen del proceso de selección
      // y pueden apuntar a storage/documentos-prospectos.
      //
      // Solo eliminamos físicamente archivos creados
      // específicamente dentro de documentos-empleados.
      // ==================================================

      const rutaNormalizada =
        String(
          documento
            .ruta_archivo ||
          ""
        )
          .replace(
            /\\/g,
            "/"
          );

      if (
        rutaNormalizada.includes(
          "/uploads/documentos-empleados/"
        )
      ) {

        await eliminarArchivoFisico(
          documento
            .nombre_archivo
        );

      }

      return res.json({

        success: true,

        message:
          "Documento eliminado correctamente"

      });

    } catch (error) {

      console.error(
        "❌ Error eliminando documento del empleado:",
        error
      );

      return res
        .status(500)
        .json({

          success: false,

          message:
            "Error interno al eliminar el documento",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined

        });

    }

  };