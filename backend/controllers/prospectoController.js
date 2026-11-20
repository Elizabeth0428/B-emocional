// ==================================================
// backend/controllers/prospectoController.js
// ==================================================

import pool from "../config/database.js";

// ==================================================
// FUNCIONES AUXILIARES
// ==================================================

const limpiarTexto = valor => {
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


const normalizar = valor =>
  valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";

// ==================================================
// CONTEXTO RH DEL USUARIO
//
// Incluye soporte para:
// - Master
// - Admin RH
// - Usuario RH
// - Independiente con perfil RH
// ==================================================

const obtenerContextoRH = async user => {
  const idUsuario =
    Number(user?.id_usuario) || null;

  if (!idUsuario) {
    return {
      idUsuario: null,
      tipoAdmin: "",
      area: "",
      rol: "",
      idAdminPadre: null,
      idOrganizacion: null,
      perfilIndependiente: "",
      esMaster: false,
      esAdminRH: false,
      esUsuarioRH: false,
      esIndependienteRH: false
    };
  }

  const [rows] =
    await pool.query(
      `
        SELECT
          u.id_usuario,
          u.tipo_admin,
          u.area,
          u.rol,
          u.id_admin_padre,
          u.id_organizacion,
          o.perfil_independiente
        FROM usuarios u
        LEFT JOIN organizaciones o
          ON o.id_organizacion = u.id_organizacion
        WHERE u.id_usuario = ?
        LIMIT 1
      `,
      [idUsuario]
    );

  const usuario = rows[0] || {};

  const tipoAdmin =
    normalizar(usuario.tipo_admin || user?.tipo_admin);

  const area =
    normalizar(usuario.area || user?.area);

  const rol =
    normalizar(usuario.rol || user?.rol);

  const perfilIndependiente =
    normalizar(
      usuario.perfil_independiente ||
      user?.perfil_independiente
    );

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
    perfilIndependiente === "rh";

  return {
    idUsuario,
    tipoAdmin,
    area,
    rol,
    idAdminPadre:
      Number(usuario.id_admin_padre || user?.id_admin_padre) || null,
    idOrganizacion:
      Number(usuario.id_organizacion || user?.id_organizacion) || null,
    perfilIndependiente,
    esMaster,
    esAdminRH,
    esUsuarioRH,
    esIndependienteRH
  };
};

const tienePermisoRH = contexto =>
  Boolean(
    contexto?.esMaster ||
    contexto?.esAdminRH ||
    contexto?.esUsuarioRH ||
    contexto?.esIndependienteRH
  );

const normalizarSexo = sexo => {
  if (!sexo) {
    return null;
  }

  const valor =
    String(sexo)
      .trim()
      .toUpperCase();

  if (
    valor === "F" ||
    valor === "FEMENINO" ||
    valor === "MUJER"
  ) {
    return "F";
  }

  if (
    valor === "M" ||
    valor === "MASCULINO" ||
    valor === "HOMBRE"
  ) {
    return "M";
  }

  return null;
};

const codigoSexoMirror = sexo => {
  return sexo === "F"
    ? "FE"
    : "MA";
};

// ==================================================
// GENERAR ID MIRRORSOUL
//
// Ejemplo:
// MS-2026-25-FE-002
// ==================================================

const generarIdMirrorProspecto = async (
  connection,
  edad,
  sexo
) => {
  const anio =
    new Date().getFullYear();

  const [filas] =
    await connection.query(
      `
        SELECT
          COALESCE(MAX(consecutivo), 0) AS ultimo
        FROM mirror_ids
        FOR UPDATE
      `
    );

  const ultimo =
    Number(
      filas?.[0]?.ultimo || 0
    );

  const consecutivo =
    ultimo + 1;

  const consecutivoTexto =
    String(consecutivo)
      .padStart(3, "0");

  const codigoSexo =
    codigoSexoMirror(
      sexo
    );

  const idMirror =
    `MS-${anio}-${edad}-${codigoSexo}-${consecutivoTexto}`;

  return {
    idMirror,
    consecutivo,
    anio
  };
};

// ==================================================
// REGISTRAR PROSPECTO
// POST /api/prospectos
// ==================================================

export const registrarProspecto = async (
  req,
  res
) => {
  let connection = null;

  try {
    const {
      nombre,
      edad,
      sexo,
      correo,
      telefono,
      puesto,
      direccion
    } = req.body;

    // ==================================================
    // VALIDAR NOMBRE
    // ==================================================

    const nombreLimpio =
      limpiarTexto(
        nombre
      );

    if (!nombreLimpio) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "El nombre del prospecto es obligatorio"
        });
    }

    // ==================================================
    // VALIDAR EDAD
    // ==================================================

    const edadNumero =
      Number(
        edad
      );

    if (
      !Number.isInteger(
        edadNumero
      ) ||
      edadNumero < 1 ||
      edadNumero > 120
    ) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "La edad del prospecto es obligatoria y debe ser válida"
        });
    }

    // ==================================================
    // VALIDAR SEXO
    // ==================================================

    const sexoNormalizado =
      normalizarSexo(
        sexo
      );

    if (!sexoNormalizado) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Selecciona un sexo válido: Femenino o Masculino"
        });
    }

    // ==================================================
    // VALIDAR CORREO
    // ==================================================

    const correoLimpio =
      limpiarTexto(
        correo
      );

    if (!correoLimpio) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "El correo del prospecto es obligatorio"
        });
    }

    const correoValido =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        correoLimpio
      );

    if (!correoValido) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Ingresa un correo electrónico válido"
        });
    }

    // ==================================================
    // USUARIO QUE REGISTRA + PERMISO RH
    // ==================================================

    const contexto =
      await obtenerContextoRH(
        req.user
      );

    const idAdminPadre =
      contexto.idUsuario;

    if (!idAdminPadre) {
      return res
        .status(401)
        .json({
          success: false,
          message:
            "No se pudo identificar al usuario que registra el prospecto"
        });
    }

    if (!tienePermisoRH(contexto)) {
      return res
        .status(403)
        .json({
          success: false,
          message:
            "No tienes permiso para registrar prospectos de Recursos Humanos"
        });
    }

    // ==================================================
    // VERIFICAR CORREO DUPLICADO
    // ==================================================

    const [existentes] =
      await pool.query(
        `
          SELECT
            id_prospecto,
            id_mirror,
            nombre,
            correo,
            estatus
          FROM prospectos
          WHERE correo = ?
            AND id_admin_padre = ?
          LIMIT 1
        `,
        [
          correoLimpio,
          idAdminPadre
        ]
      );

    if (
      existentes.length > 0
    ) {
      return res
        .status(409)
        .json({
          success: false,
          message:
            "Ya existe un prospecto registrado con ese correo en tus registros",
          prospecto:
            existentes[0]
        });
    }

    // ==================================================
    // INICIAR TRANSACCIÓN
    // ==================================================

    connection =
      await pool.getConnection();

    await connection
      .beginTransaction();

    // ==================================================
    // GENERAR ID MIRRORSOUL
    // ==================================================

    const {
      idMirror,
      consecutivo,
      anio
    } =
      await generarIdMirrorProspecto(
        connection,
        edadNumero,
        sexoNormalizado
      );

    // ==================================================
    // INSERTAR PROSPECTO
    // ==================================================

    const [resultado] =
      await connection.query(
        `
          INSERT INTO prospectos
          (
            id_admin_padre,
            nombre,
            edad,
            sexo,
            id_mirror,
            correo,
            telefono,
            puesto,
            direccion,
            estatus,
            fecha_registro
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
            'en_proceso',
            NOW()
          )
        `,
        [
          idAdminPadre,
          nombreLimpio,
          edadNumero,
          sexoNormalizado,
          idMirror,
          correoLimpio,
          limpiarTexto(
            telefono
          ),
          limpiarTexto(
            puesto
          ),
          limpiarTexto(
            direccion
          )
        ]
      );

    const idProspecto =
      resultado.insertId;

    // ==================================================
    // REGISTRAR ID EN MIRROR_IDS
    // ==================================================

    await connection.query(
      `
        INSERT INTO mirror_ids
        (
          id_mirror,
          consecutivo,
          año,
          tipo_persona,
          id_referencia,
          fecha_registro
        )
        VALUES
        (
          ?,
          ?,
          ?,
          'prospecto',
          ?,
          NOW()
        )
      `,
      [
        idMirror,
        consecutivo,
        anio,
        idProspecto
      ]
    );

    await connection.commit();

    console.log(
      "✅ Prospecto RH registrado:",
      {
        id_prospecto:
          idProspecto,

        id_mirror:
          idMirror,

        nombre:
          nombreLimpio,

        edad:
          edadNumero,

        sexo:
          sexoNormalizado,

        estatus:
          "en_proceso",

        id_admin_padre:
          idAdminPadre
      }
    );

    return res
      .status(201)
      .json({
        success: true,

        message:
          "Prospecto registrado correctamente",

        prospecto: {
          id_prospecto:
            idProspecto,

          id_mirror:
            idMirror,

          nombre:
            nombreLimpio,

          edad:
            edadNumero,

          sexo:
            sexoNormalizado,

          correo:
            correoLimpio,

          telefono:
            limpiarTexto(
              telefono
            ),

          puesto:
            limpiarTexto(
              puesto
            ),

          direccion:
            limpiarTexto(
              direccion
            ),

          estatus:
            "en_proceso",

          id_admin_padre:
            idAdminPadre
        }
      });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (
        rollbackError
      ) {
        console.error(
          "❌ Error haciendo rollback:",
          rollbackError
        );
      }
    }

    console.error(
      "❌ Error al registrar prospecto:",
      error
    );

    if (
      error?.code ===
      "ER_DUP_ENTRY"
    ) {
      return res
        .status(409)
        .json({
          success: false,
          message:
            "No fue posible generar el ID MirrorSoul. Intenta registrar nuevamente."
        });
    }

    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error interno al registrar prospecto",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// LISTAR PROSPECTOS
// GET /api/prospectos
//
// DEVUELVE:
// - activos
// - contratados
// - no contratados
//
// IMPORTANTE:
//
// Un usuario RH ve:
//
// 1. Los prospectos que él registró.
// 2. El historial CONTRATADO de los empleados
//    que actualmente tiene asignados.
//
// El creador original NO se modifica.
// ==================================================

export const listarProspectos = async (
  req,
  res
) => {
  try {
    const contexto =
      await obtenerContextoRH(
        req.user
      );

    const idUsuario =
      contexto.idUsuario;

    if (!idUsuario) {
      return res
        .status(401)
        .json({
          success: false,
          message:
            "No se pudo identificar al usuario"
        });
    }

    if (!tienePermisoRH(contexto)) {
      return res
        .status(403)
        .json({
          success: false,
          message:
            "No tienes permiso para consultar prospectos de Recursos Humanos"
        });
    }

    const tipoAdmin =
      contexto.tipoAdmin;

    let query = `
      SELECT
        p.id_prospecto,
        p.id_mirror,
        p.nombre,
        p.edad,
        p.sexo,
        p.correo,
        p.telefono,
        p.puesto,
        p.direccion,
        p.estatus,
        p.id_admin_padre,
        p.fecha_registro,
        p.fecha_actualizacion,

        COALESCE(
          rpc.decision,
          rse.decision
        ) AS decision_cierre,

        COALESCE(
          rpc.motivo,
          rse.motivo
        ) AS motivo,

        COALESCE(
          rpc.observacion_final,
          rse.observacion_final
        ) AS observacion_final,

        COALESCE(
          rpc.resumen_pruebas,
          rse.resumen_pruebas
        ) AS resumen_pruebas,

        COALESCE(
          rpc.fecha_decision,
          rse.fecha_decision
        ) AS fecha_decision,

        e.id_empleado,

        e.id_usuario_responsable

      FROM prospectos p

      LEFT JOIN resumen_prospectos_cerrados rpc
        ON rpc.id_prospecto =
           p.id_prospecto

      LEFT JOIN empleados e
        ON e.id_prospecto =
           p.id_prospecto

      LEFT JOIN resumen_seleccion_empleados rse
        ON rse.id_empleado =
           e.id_empleado
    `;

    const params = [];

    // ==================================================
    // RH NORMAL
    //
    // VE:
    //
    // 1. LOS PROSPECTOS QUE ÉL REGISTRÓ.
    //
    // 2. EL HISTORIAL CONTRATADO DE EMPLEADOS
    //    QUE ACTUALMENTE TIENE ASIGNADOS.
    //
    // IMPORTANTE:
    //
    // p.id_admin_padre NO SE CAMBIA.
    // ==================================================

    if (
      tipoAdmin !== "master"
    ) {
      query += `
        WHERE
        (
          p.id_admin_padre = ?

          OR

          (
            LOWER(
              TRIM(
                COALESCE(
                  p.estatus,
                  ''
                )
              )
            ) = 'contratado'

            AND e.id_usuario_responsable = ?
          )
        )
      `;

      params.push(
        idUsuario,
        idUsuario
      );
    }

    query += `
      ORDER BY
        COALESCE(
          rpc.fecha_decision,
          rse.fecha_decision,
          p.fecha_actualizacion,
          p.fecha_registro
        ) DESC,

        p.id_prospecto DESC
    `;

    const [prospectos] =
      await pool.query(
        query,
        params
      );

    console.log(
      tipoAdmin === "master"
        ? "📦 Prospectos Master:"
        : "📦 Prospectos RH:",
      {
        idUsuario,

        total:
          prospectos.length,

        activos:
          prospectos.filter(
            p =>
              ![
                "contratado",
                "no_contratado"
              ].includes(
                String(
                  p.estatus ||
                  ""
                )
                  .trim()
                  .toLowerCase()
              )
          ).length,

        cerrados:
          prospectos.filter(
            p =>
              [
                "contratado",
                "no_contratado"
              ].includes(
                String(
                  p.estatus ||
                  ""
                )
                  .trim()
                  .toLowerCase()
              )
          ).length
      }
    );

    return res.json({
      success: true,
      prospectos
    });

  } catch (error) {
    console.error(
      "❌ Error al listar prospectos:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error interno al obtener los prospectos",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });
  }
};

// ==================================================
// OBTENER UN PROSPECTO
// GET /api/prospectos/:id
//
// PERMITE:
//
// - creador original
// - Master
// - responsable RH actual del empleado contratado
// ==================================================

export const obtenerProspecto = async (
  req,
  res
) => {
  try {
    const idProspecto =
      Number(
        req.params.id
      );

    if (
      !Number.isInteger(
        idProspecto
      ) ||
      idProspecto <= 0
    ) {
      return res
        .status(400)
        .json({
          success: false,

          message:
            "ID de prospecto inválido"
        });
    }

    const contexto =
      await obtenerContextoRH(
        req.user
      );

    const idUsuario =
      contexto.idUsuario;

    if (!idUsuario) {
      return res
        .status(401)
        .json({
          success: false,
          message:
            "No se pudo identificar al usuario"
        });
    }

    if (!tienePermisoRH(contexto)) {
      return res
        .status(403)
        .json({
          success: false,
          message:
            "No tienes permiso para consultar prospectos"
        });
    }

    const tipoAdmin =
      contexto.tipoAdmin;

    let query = `
      SELECT
        id_prospecto,
        id_mirror,
        nombre,
        edad,
        sexo,
        correo,
        telefono,
        puesto,
        direccion,
        estatus,
        id_admin_padre,
        fecha_registro,
        fecha_actualizacion

      FROM prospectos

      WHERE
        id_prospecto = ?
    `;

    const params = [
      idProspecto
    ];

    if (
      tipoAdmin !== "master"
    ) {
      query += `
        AND
        (
          id_admin_padre = ?

          OR

          (
            LOWER(
              TRIM(
                COALESCE(
                  estatus,
                  ''
                )
              )
            ) = 'contratado'

            AND EXISTS
            (
              SELECT 1

              FROM empleados e

              WHERE
                e.id_prospecto =
                  prospectos.id_prospecto

                AND e.id_usuario_responsable = ?
            )
          )
        )
      `;

      params.push(
        idUsuario,
        idUsuario
      );
    }

    query += `
      LIMIT 1
    `;

    const [resultados] =
      await pool.query(
        query,
        params
      );

    if (
      resultados.length === 0
    ) {
      return res
        .status(404)
        .json({
          success: false,

          message:
            "Prospecto no encontrado"
        });
    }

    return res.json({
      success: true,

      prospecto:
        resultados[0]
    });

  } catch (error) {
    console.error(
      "❌ Error al obtener prospecto:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error interno al obtener el prospecto",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });
  }
};