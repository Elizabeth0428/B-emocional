import pool from "../config/database.js";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename =
  fileURLToPath(
    import.meta.url
  );

const __dirname =
  path.dirname(
    __filename
  );

// ==================================================
// CARPETA
// ==================================================

const evidenciasPath =
  path.join(
    __dirname,
    "..",
    "uploads",
    "evidencias-seguimiento-empleados"
  );

fs.mkdirSync(
  evidenciasPath,
  {
    recursive: true
  }
);

// ==================================================
// MIME
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

const TIPOS_EVIDENCIA = [
  "documento",
  "acta",
  "correo",
  "imagen",
  "constancia",
  "carta",
  "otro"
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
          evidenciasPath
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
            .substring(
              2,
              10
            )}${extension}`;

        cb(
          null,
          nombre
        );
      }
  });

export const uploadEvidenciaSeguimiento =
  multer({
    storage,

    limits: {
      fileSize:
        10 *
        1024 *
        1024
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
// AUXILIARES
// ==================================================

const normalizar = valor =>
  valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";

const limpiarTexto =
  valor => {
    if (
      valor ===
        undefined ||
      valor ===
        null
    ) {
      return null;
    }

    const resultado =
      String(
        valor
      ).trim();

    return resultado ||
      null;
  };

const eliminarArchivoFisico =
  async nombreArchivo => {
    if (!nombreArchivo) {
      return;
    }

    const ruta =
      path.join(
        evidenciasPath,
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
          "⚠️ Error eliminando archivo físico:",
          error
        );
      }
    }
  };

// ==================================================
// CONTEXTO DEL USUARIO
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

    if (!idUsuario) {
      return {
        idUsuario: null,
        tipoAdmin: "",
        area: "",
        rol: "",
        idAdminPadre: null,
        idOrganizacion: null,
        perfilIndependiente: "",
        estadoOrganizacion: ""
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

    if (!rows.length) {
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
// VALIDAR ACCESO
// ==================================================

const validarAccesoSeguimiento =
  async (
    idEmpleado,
    idSeguimiento,
    user,
    connection = pool
  ) => {
    const contexto =
      await obtenerContextoUsuario(
        user,
        connection
      );

    if (!contexto.idUsuario) {
      return {
        ok: false,
        status: 401,
        message:
          "No se pudo identificar al usuario"
      };
    }

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
          "No tienes permiso para acceder a las evidencias"
      };
    }

    let query = `
      SELECT
        e.id_empleado,
        e.id_admin_padre,
        e.id_usuario_responsable,

        s.id_seguimiento,
        s.estado AS estado_seguimiento

      FROM empleados e

      INNER JOIN seguimiento_empleados s
        ON s.id_empleado =
           e.id_empleado

      WHERE
        e.id_empleado = ?

        AND s.id_seguimiento = ?
    `;

    const params = [
      idEmpleado,
      idSeguimiento
    ];

    if (esAdminRH) {
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

    if (!rows.length) {
      return {
        ok: false,
        status: 404,
        message:
          "Seguimiento no encontrado o no tienes permiso para acceder"
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

      seguimiento:
        rows[0]
    };
  };

// ==================================================
// LISTAR EVIDENCIAS
//
// GET
// /api/empleados/:id/seguimiento/:idSeguimiento/evidencias
// ==================================================

export const listarEvidenciasSeguimiento =
  async (
    req,
    res
  ) => {
    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idSeguimiento =
        Number(
          req.params
            .idSeguimiento
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idSeguimiento
        ) ||
        idSeguimiento <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Datos inválidos"
          });
      }

      const acceso =
        await validarAccesoSeguimiento(
          idEmpleado,
          idSeguimiento,
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

      const [evidencias] =
        await pool.query(
          `
            SELECT
              ev.*,

              ur.nombre
                AS usuario_registro,

              ua.nombre
                AS usuario_anulacion

            FROM evidencias_seguimiento_empleados ev

            LEFT JOIN usuarios ur
              ON ur.id_usuario =
                 ev.id_usuario_registro

            LEFT JOIN usuarios ua
              ON ua.id_usuario =
                 ev.id_usuario_anulacion

            WHERE
              ev.id_empleado = ?

              AND ev.id_seguimiento = ?

            ORDER BY
              ev.fecha_subida DESC,
              ev.id_evidencia DESC
          `,
          [
            idEmpleado,
            idSeguimiento
          ]
        );

      return res.json({
        success: true,

        total:
          evidencias.length,

        evidencias
      });

    } catch (error) {
      console.error(
        "❌ Error listando evidencias:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al obtener las evidencias"
        });
    }
  };

// ==================================================
// SUBIR EVIDENCIA
//
// POST
// /api/empleados/:id/seguimiento/:idSeguimiento/evidencias
// ==================================================

export const subirEvidenciaSeguimiento =
  async (
    req,
    res
  ) => {
    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idSeguimiento =
        Number(
          req.params
            .idSeguimiento
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idSeguimiento
        ) ||
        idSeguimiento <= 0
      ) {
        if (req.file) {
          await eliminarArchivoFisico(
            req.file.filename
          );
        }

        return res
          .status(400)
          .json({
            success: false,

            message:
              "Datos inválidos"
          });
      }

      const acceso =
        await validarAccesoSeguimiento(
          idEmpleado,
          idSeguimiento,
          req.user
        );

      if (!acceso.ok) {
        if (req.file) {
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

      if (!req.file) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Selecciona un archivo"
          });
      }

      let tipoEvidencia =
        normalizar(
          req.body
            ?.tipo_evidencia ||
          "documento"
        );

      if (
        !TIPOS_EVIDENCIA
          .includes(
            tipoEvidencia
          )
      ) {
        tipoEvidencia =
          "otro";
      }

      const rutaArchivo =
        `/uploads/evidencias-seguimiento-empleados/${req.file.filename}`;

      const [resultado] =
        await pool.query(
          `
            INSERT INTO evidencias_seguimiento_empleados
            (
              id_seguimiento,
              id_empleado,
              id_usuario_registro,
              tipo_evidencia,
              titulo,
              descripcion,
              nombre_original,
              nombre_archivo,
              ruta_archivo,
              mime_type,
              fecha_evidencia,
              fecha_subida,
              estado
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
              ?,
              ?,
              ?,
              NOW(),
              'activo'
            )
          `,
          [
            idSeguimiento,
            idEmpleado,

            acceso.contexto
              .idUsuario,

            tipoEvidencia,

            limpiarTexto(
              req.body?.titulo
            ),

            limpiarTexto(
              req.body
                ?.descripcion
            ),

            req.file
              .originalname,

            req.file
              .filename,

            rutaArchivo,

            req.file
              .mimetype ||
              null,

            req.body
              ?.fecha_evidencia ||
              null
          ]
        );

      const [rows] =
        await pool.query(
          `
            SELECT
              ev.*,

              u.nombre
                AS usuario_registro

            FROM evidencias_seguimiento_empleados ev

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 ev.id_usuario_registro

            WHERE
              ev.id_evidencia = ?

            LIMIT 1
          `,
          [
            resultado.insertId
          ]
        );

      return res
        .status(201)
        .json({
          success: true,

          message:
            "Evidencia agregada correctamente",

          evidencia:
            rows[0] ||
            null
        });

    } catch (error) {
      if (req.file) {
        await eliminarArchivoFisico(
          req.file.filename
        );
      }

      console.error(
        "❌ Error subiendo evidencia:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al guardar la evidencia",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined
        });
    }
  };

// ==================================================
// ANULAR EVIDENCIA
//
// DELETE
// /api/empleados/:id/seguimiento/:idSeguimiento/evidencias/:idEvidencia
//
// NO BORRAMOS.
// ==================================================

export const anularEvidenciaSeguimiento =
  async (
    req,
    res
  ) => {
    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idSeguimiento =
        Number(
          req.params
            .idSeguimiento
        );

      const idEvidencia =
        Number(
          req.params
            .idEvidencia
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idSeguimiento
        ) ||
        idSeguimiento <= 0 ||
        !Number.isInteger(
          idEvidencia
        ) ||
        idEvidencia <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Datos inválidos"
          });
      }

      const motivo =
        limpiarTexto(
          req.body
            ?.motivo_anulacion
        );

      if (!motivo) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Debes indicar el motivo de la anulación"
          });
      }

      const acceso =
        await validarAccesoSeguimiento(
          idEmpleado,
          idSeguimiento,
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
              id_evidencia,
              estado

            FROM evidencias_seguimiento_empleados

            WHERE
              id_evidencia = ?

              AND id_empleado = ?

              AND id_seguimiento = ?

            LIMIT 1
          `,
          [
            idEvidencia,
            idEmpleado,
            idSeguimiento
          ]
        );

      if (!rows.length) {
        return res
          .status(404)
          .json({
            success: false,

            message:
              "Evidencia no encontrada"
          });
      }

      if (
        rows[0].estado ===
        "anulado"
      ) {
        return res
          .status(409)
          .json({
            success: false,

            message:
              "La evidencia ya se encuentra anulada"
          });
      }

      await pool.query(
        `
          UPDATE evidencias_seguimiento_empleados

          SET
            estado =
              'anulado',

            motivo_anulacion = ?,

            fecha_anulacion =
              NOW(),

            id_usuario_anulacion = ?

          WHERE
            id_evidencia = ?

            AND id_empleado = ?

            AND id_seguimiento = ?
        `,
        [
          motivo,

          acceso.contexto
            .idUsuario,

          idEvidencia,
          idEmpleado,
          idSeguimiento
        ]
      );

      return res.json({
        success: true,

        message:
          "Evidencia anulada correctamente. El registro se conserva en el expediente."
      });

    } catch (error) {
      console.error(
        "❌ Error anulando evidencia:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al anular la evidencia"
        });
    }
  };