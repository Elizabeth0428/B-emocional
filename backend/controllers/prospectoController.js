// ==================================================
// backend/controllers/prospectoController.js
// ==================================================

import pool from "../config/database.js";

// ==================================================
// FUNCIONES AUXILIARES
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

const normalizarSexo = (sexo) => {
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

const codigoSexoMirror = (sexo) => {
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
    anio,
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
      direccion,
    } = req.body;

    // ==================================================
    // VALIDAR NOMBRE
    // ==================================================

    const nombreLimpio =
      limpiarTexto(
        nombre
      );

    if (!nombreLimpio) {
      return res.status(400).json({
        success: false,
        message:
          "El nombre del prospecto es obligatorio",
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
      return res.status(400).json({
        success: false,
        message:
          "La edad del prospecto es obligatoria y debe ser válida",
      });
    }

    // ==================================================
    // VALIDAR SEXO
    // ==================================================

    const sexoNormalizado =
      normalizarSexo(
        sexo
      );

    if (
      !sexoNormalizado
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Selecciona un sexo válido: Femenino o Masculino",
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
      return res.status(400).json({
        success: false,
        message:
          "El correo del prospecto es obligatorio",
      });
    }

    const correoValido =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        correoLimpio
      );

    if (
      !correoValido
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Ingresa un correo electrónico válido",
      });
    }

    // ==================================================
    // ADMINISTRADOR QUE REGISTRA
    // ==================================================

    const idAdminPadre =
      req.user?.id_usuario ||
      null;

    if (
      !idAdminPadre
    ) {
      return res.status(401).json({
        success: false,
        message:
          "No se pudo identificar al administrador que registra el prospecto",
      });
    }

    // ==================================================
    // INFORMACIÓN DEL ADMIN
    // ==================================================

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(
            req.user.tipo_admin
          )
            .trim()
            .toLowerCase()
        : null;

    const area =
      req.user?.area
        ? String(
            req.user.area
          )
            .trim()
            .toLowerCase()
        : null;

    // ==================================================
    // SOLO RH O MASTER
    // ==================================================

    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Solo los administradores de Recursos Humanos pueden registrar prospectos",
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
          idAdminPadre,
        ]
      );

    if (
      existentes.length > 0
    ) {
      return res.status(409).json({
        success: false,
        message:
          "Ya existe un prospecto registrado con ese correo en tus registros",
        prospecto:
          existentes[0],
      });
    }

    // ==================================================
    // INICIAR TRANSACCIÓN
    // ==================================================

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    // ==================================================
    // GENERAR ID MIRRORSOUL
    // ==================================================

    const {
      idMirror,
      consecutivo,
      anio,
    } =
      await generarIdMirrorProspecto(
        connection,
        edadNumero,
        sexoNormalizado
      );

    // ==================================================
    // INSERTAR PROSPECTO
    //
    // NUEVO PROSPECTO = EN PROCESO
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
          ),
        ]
      );

    const idProspecto =
      resultado.insertId;

    // ==================================================
    // REGISTRAR ID EN MIRROR_IDS
    //
    // tipo_persona sigue siendo "prospecto".
    // Esto identifica el TIPO DE PERSONA,
    // no el estado del proceso.
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
        idProspecto,
      ]
    );

    // ==================================================
    // CONFIRMAR
    // ==================================================

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
          idAdminPadre,
      }
    );

    // ==================================================
    // RESPUESTA
    // ==================================================

    return res.status(201).json({
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
          idAdminPadre,
      },
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
      return res.status(409).json({
        success: false,

        message:
          "No fue posible generar el ID MirrorSoul. Intenta registrar nuevamente.",
      });
    }

    return res.status(500).json({
      success: false,

      message:
        "Error interno al registrar prospecto",

      error:
        process.env.NODE_ENV ===
        "development"
          ? error.message
          : undefined,
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
// SOLO PROSPECTOS ACTIVOS.
//
// contratado y no_contratado ya terminaron
// el proceso y NO deben aparecer aquí.
// ==================================================

export const listarProspectos = async (
  req,
  res
) => {
  try {
    const idUsuario =
      req.user?.id_usuario;

    if (
      !idUsuario
    ) {
      return res.status(401).json({
        success: false,

        message:
          "No se pudo identificar al usuario",
      });
    }

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(
            req.user.tipo_admin
          )
            .trim()
            .toLowerCase()
        : null;

    const area =
      req.user?.area
        ? String(
            req.user.area
          )
            .trim()
            .toLowerCase()
        : null;

    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {
      return res.status(403).json({
        success: false,

        message:
          "Solo los administradores de Recursos Humanos pueden consultar prospectos",
      });
    }

    // ==================================================
    // MASTER
    // ==================================================

    if (
      tipoAdmin ===
      "master"
    ) {
      const [prospectos] =
        await pool.query(
          `
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

            WHERE estatus NOT IN
            (
              'contratado',
              'no_contratado'
            )

            ORDER BY
              fecha_registro DESC,
              id_prospecto DESC
          `
        );

      return res.json({
        success: true,
        prospectos,
      });
    }

    // ==================================================
    // RH NORMAL
    // ==================================================

    const [prospectos] =
      await pool.query(
        `
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

          WHERE id_admin_padre = ?

            AND estatus NOT IN
            (
              'contratado',
              'no_contratado'
            )

          ORDER BY
            fecha_registro DESC,
            id_prospecto DESC
        `,
        [
          idUsuario,
        ]
      );

    return res.json({
      success: true,
      prospectos,
    });

  } catch (error) {
    console.error(
      "❌ Error al listar prospectos:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "Error interno al obtener los prospectos",

      error:
        process.env.NODE_ENV ===
        "development"
          ? error.message
          : undefined,
    });
  }
};

// ==================================================
// OBTENER UN PROSPECTO
// GET /api/prospectos/:id
//
// Aquí SÍ permitimos consultar el registro aunque
// posteriormente esté contratado.
//
// Esto es útil para historial / referencias internas.
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
      return res.status(400).json({
        success: false,

        message:
          "ID de prospecto inválido",
      });
    }

    const idUsuario =
      req.user?.id_usuario;

    if (
      !idUsuario
    ) {
      return res.status(401).json({
        success: false,

        message:
          "No se pudo identificar al usuario",
      });
    }

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(
            req.user.tipo_admin
          )
            .trim()
            .toLowerCase()
        : null;

    const area =
      req.user?.area
        ? String(
            req.user.area
          )
            .trim()
            .toLowerCase()
        : null;

    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {
      return res.status(403).json({
        success: false,

        message:
          "No tienes permiso para consultar prospectos",
      });
    }

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

      WHERE id_prospecto = ?
    `;

    const params = [
      idProspecto,
    ];

    if (
      tipoAdmin !==
      "master"
    ) {
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

    const [resultados] =
      await pool.query(
        query,
        params
      );

    if (
      resultados.length === 0
    ) {
      return res.status(404).json({
        success: false,

        message:
          "Prospecto no encontrado",
      });
    }

    return res.json({
      success: true,

      prospecto:
        resultados[0],
    });

  } catch (error) {
    console.error(
      "❌ Error al obtener prospecto:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "Error interno al obtener el prospecto",

      error:
        process.env.NODE_ENV ===
        "development"
          ? error.message
          : undefined,
    });
  }
};