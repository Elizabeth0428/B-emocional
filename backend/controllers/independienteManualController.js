// ============================================================
// backend/controllers/independienteManualController.js
// Alta manual de membresía Independiente - SOLO MASTER
// ============================================================

import bcrypt from "bcryptjs";
import pool from "../config/database.js";


// ============================================================
// VALIDAR MASTER
// ============================================================

function esMaster(req) {

  return (
    Number(
      req.user?.role
    ) === 1 &&

    String(
      req.user?.tipo_admin || ""
    )
      .trim()
      .toLowerCase() ===
      "master"
  );

}


// ============================================================
// LIMPIAR TEXTO
// ============================================================

function limpiarTexto(valor) {

  if (
    valor === undefined ||
    valor === null
  ) {

    return null;

  }


  const limpio =
    String(
      valor
    ).trim();


  return limpio || null;

}


// ============================================================
// NORMALIZAR CORREO
// ============================================================

function normalizarCorreo(valor) {

  if (!valor) {

    return null;

  }


  return String(
    valor
  )
    .trim()
    .toLowerCase();

}


// ============================================================
// FECHA SQL
// ============================================================

function fechaSQL(fecha) {

  const anio =
    fecha.getFullYear();


  const mes =
    String(
      fecha.getMonth() + 1
    )
      .padStart(
        2,
        "0"
      );


  const dia =
    String(
      fecha.getDate()
    )
      .padStart(
        2,
        "0"
      );


  return `${anio}-${mes}-${dia}`;

}


// ============================================================
// SUMAR MESES
// ============================================================

function sumarMeses(
  fecha,
  meses
) {

  const nueva =
    new Date(
      fecha
    );


  nueva.setMonth(
    nueva.getMonth() +
    Number(
      meses
    )
  );


  return nueva;

}


// ============================================================
// CREAR INDEPENDIENTE MANUAL
//
// POST
// /api/independientes-manual
//
// SOLO MASTER
//
// CREA:
//
// - organización independiente
// - titular independiente
// - suscripción activa
// - 1 licencia
// - licencia asignada al titular
//
// ============================================================

export async function crearIndependienteManual(
  req,
  res
) {

  let connection;


  try {

    // ========================================================
    // VALIDAR MASTER
    // ========================================================

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Solo el Administrador Master puede crear membresías independientes manuales."

        });

    }


    // ========================================================
    // DATOS
    // ========================================================

    const {

      perfil_independiente,

      nombre,

      nombre_practica,

      correo,

      password,

      telefono,

      direccion,

      rfc,

      id_plan,

      meses = 1,

      origen_alta =
        "cortesia",

      motivo_alta =
        null

    } =
      req.body || {};


    // ========================================================
    // NORMALIZAR
    // ========================================================

    const perfil =
      String(
        perfil_independiente ||
        ""
      )
        .trim()
        .toLowerCase();


    const nombreFinal =
      limpiarTexto(
        nombre
      );


    const practicaFinal =
      limpiarTexto(
        nombre_practica
      );


    const correoFinal =
      normalizarCorreo(
        correo
      );


    const telefonoFinal =
      limpiarTexto(
        telefono
      );


    const direccionFinal =
      limpiarTexto(
        direccion
      );


    const rfcFinal =
      limpiarTexto(
        rfc
      );


    const idPlan =
      Number(
        id_plan
      );


    const mesesFinal =
      Number(
        meses
      );


    // ========================================================
    // VALIDAR PERFIL
    // ========================================================

    if (
      ![
        "clinica",
        "rh"
      ].includes(
        perfil
      )
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "Selecciona un perfil independiente válido: Clínica/Psicología o Recursos Humanos."

        });

    }


    // ========================================================
    // VALIDAR NOMBRE
    // ========================================================

    if (
      !nombreFinal
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "El nombre del titular es obligatorio."

        });

    }


    // ========================================================
    // VALIDAR PRÁCTICA
    // ========================================================

    if (
      !practicaFinal
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "El nombre de la práctica o espacio es obligatorio."

        });

    }


    // ========================================================
    // VALIDAR CORREO
    // ========================================================

    if (
      !correoFinal
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "El correo es obligatorio."

        });

    }


    // ========================================================
    // VALIDAR CONTRASEÑA
    // ========================================================

    if (
      !password ||
      String(
        password
      ).length < 6
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "La contraseña debe tener al menos 6 caracteres."

        });

    }


    // ========================================================
    // VALIDAR PLAN
    // ========================================================

    if (
      !Number.isInteger(
        idPlan
      ) ||
      idPlan <= 0
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "Selecciona un plan Independiente."

        });

    }


    // ========================================================
    // VALIDAR MESES
    // ========================================================

    if (
      !Number.isInteger(
        mesesFinal
      ) ||
      mesesFinal < 1 ||
      mesesFinal > 36
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "La vigencia debe ser de 1 a 36 meses."

        });

    }


    // ========================================================
    // ABRIR TRANSACCIÓN
    // ========================================================

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ========================================================
    // VALIDAR CORREO DUPLICADO
    // ========================================================

    const [
      usuariosExistentes
    ] =
      await connection
        .query(
          `
            SELECT
              id_usuario

            FROM usuarios

            WHERE
              LOWER(
                TRIM(correo)
              ) =
              LOWER(
                TRIM(?)
              )

            LIMIT 1

            FOR UPDATE
          `,
          [
            correoFinal
          ]
        );


    if (
      usuariosExistentes.length
    ) {

      const error =
        new Error(
          "Ya existe un usuario registrado con ese correo."
        );


      error.status =
        409;


      throw error;

    }


    // ========================================================
    // BUSCAR PLAN
    // ========================================================

    const [
      planes
    ] =
      await connection
        .query(
          `
            SELECT
              id_plan,
              nombre,
              tipo,
              licencias_incluidas,
              activo

            FROM planes

            WHERE
              id_plan = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            idPlan
          ]
        );


    if (
      !planes.length
    ) {

      const error =
        new Error(
          "El plan seleccionado no existe."
        );


      error.status =
        404;


      throw error;

    }


    const plan =
      planes[0];


    const tipoPlan =
      String(
        plan.tipo ||
        ""
      )
        .trim()
        .toLowerCase();


    // ========================================================
    // VALIDAR PLAN ACTIVO
    // ========================================================

    if (
      Number(
        plan.activo
      ) !== 1
    ) {

      const error =
        new Error(
          "El plan seleccionado no está activo."
        );


      error.status =
        400;


      throw error;

    }


    // ========================================================
    // VALIDAR QUE SEA INDEPENDIENTE
    // ========================================================

    if (
      ![
        "independiente",
        "psicologo"
      ].includes(
        tipoPlan
      )
    ) {

      const error =
        new Error(
          "El plan seleccionado no corresponde a una membresía Independiente."
        );


      error.status =
        400;


      throw error;

    }


    // ========================================================
    // CREAR ORGANIZACIÓN INDEPENDIENTE
    // ========================================================

    const [
      organizacionInsert
    ] =
      await connection
        .query(
          `
            INSERT INTO organizaciones
            (
              nombre,
              nombre_comercial,
              responsable,
              correo,
              telefono,
              rfc,
              direccion,
              tipo,
              perfil_independiente,
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
              'independiente',
              ?,
              'activa'
            )
          `,
          [
            practicaFinal,
            practicaFinal,
            nombreFinal,
            correoFinal,
            telefonoFinal,
            rfcFinal,
            direccionFinal,
            perfil
          ]
        );


    const idOrganizacion =
      organizacionInsert
        .insertId;


    // ========================================================
    // ENCRIPTAR CONTRASEÑA
    // ========================================================

    const passwordHash =
      await bcrypt.hash(
        String(
          password
        ),
        10
      );


    // ========================================================
    // CREAR TITULAR
    // ========================================================

    const [
      usuarioInsert
    ] =
      await connection
        .query(
          `
            INSERT INTO usuarios
            (
              nombre,
              correo,
              matricula,
              password,
              debe_cambiar_password,
              rol,
              tipo_admin,
              area,
              id_admin_padre,
              id_organizacion,
              estado,
              telefono,
              direccion
            )

            VALUES
            (
              ?,
              ?,
              NULL,
              ?,
              0,
              'independiente',
              NULL,
              'independiente',
              NULL,
              ?,
              'activo',
              ?,
              ?
            )
          `,
          [
            nombreFinal,
            correoFinal,
            passwordHash,
            idOrganizacion,
            telefonoFinal,
            direccionFinal
          ]
        );


    const idUsuario =
      usuarioInsert
        .insertId;


    // ========================================================
    // FECHAS
    // ========================================================

    const hoy =
      new Date();


    const fechaInicio =
      fechaSQL(
        hoy
      );


    const proximaRenovacion =
      fechaSQL(
        sumarMeses(
          hoy,
          mesesFinal
        )
      );


    // ========================================================
    // CREAR SUSCRIPCIÓN
    // ========================================================

    const [
      suscripcionInsert
    ] =
      await connection
        .query(
          `
            INSERT INTO suscripciones
            (
              id_organizacion,
              id_plan,
              estado,
              fecha_inicio,
              fecha_fin,
              proxima_renovacion,
              licencias_totales
            )

            VALUES
            (
              ?,
              ?,
              'activa',
              ?,
              NULL,
              ?,
              1
            )
          `,
          [
            idOrganizacion,
            idPlan,
            fechaInicio,
            proximaRenovacion
          ]
        );


    const idSuscripcion =
      suscripcionInsert
        .insertId;


    // ========================================================
    // CREAR LICENCIA Y ASIGNARLA
    // ========================================================

    const [
      licenciaInsert
    ] =
      await connection
        .query(
          `
            INSERT INTO licencias
            (
              id_suscripcion,
              id_usuario,
              tipo,
              estado,
              fecha_asignacion
            )

            VALUES
            (
              ?,
              ?,
              'independiente',
              'asignada',
              NOW()
            )
          `,
          [
            idSuscripcion,
            idUsuario
          ]
        );


    const idLicencia =
      licenciaInsert
        .insertId;


    // ========================================================
    // CONFIRMAR TRANSACCIÓN
    // ========================================================

    await connection
      .commit();


    // ========================================================
    // RESPUESTA
    // ========================================================

    return res
      .status(
        201
      )
      .json({

        success:
          true,

        message:
          "Membresía Independiente creada y activada correctamente.",

        origen_alta:
          "manual",

        tipo_beneficio:
          origen_alta,

        motivo_alta:
          motivo_alta ||
          null,


        usuario: {

          id_usuario:
            idUsuario,

          nombre:
            nombreFinal,

          correo:
            correoFinal,

          rol:
            "independiente",

          area:
            "independiente",

          id_organizacion:
            idOrganizacion

        },


        organizacion: {

          id_organizacion:
            idOrganizacion,

          nombre:
            practicaFinal,

          tipo:
            "independiente",

          perfil_independiente:
            perfil,

          estado:
            "activa"

        },


        suscripcion: {

          id_suscripcion:
            idSuscripcion,

          id_plan:
            idPlan,

          plan:
            plan.nombre,

          estado:
            "activa",

          licencias_totales:
            1,

          fecha_inicio:
            fechaInicio,

          proxima_renovacion:
            proximaRenovacion

        },


        licencia: {

          id_licencia:
            idLicencia,

          id_usuario:
            idUsuario,

          tipo:
            "independiente",

          estado:
            "asignada"

        }

      });

  }

  catch (
    error
  ) {

    // ========================================================
    // ROLLBACK
    // ========================================================

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      }

      catch {

        // nada

      }

    }


    console.error(
      "❌ Error creando independiente manual:",
      error
    );


    return res
      .status(
        error.status ||
        500
      )
      .json({

        success:
          false,

        message:
          error.message ||
          "Error interno al crear la membresía Independiente."

      });

  }

  finally {

    if (
      connection
    ) {

      connection
        .release();

    }

  }

}