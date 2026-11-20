// ==================================================
// backend/controllers/planController.js
// ==================================================

import pool from "../config/database.js";


// ==================================================
// AUXILIARES
// ==================================================

const normalizarTexto = valor => {

  if (
    valor === undefined ||
    valor === null
  ) {

    return "";

  }

  return String(valor)
    .trim();

};


const normalizarTipo = valor => {

  return normalizarTexto(
    valor
  ).toLowerCase();

};


const numeroEntero = valor => {

  const numero =
    Number(valor);

  if (
    !Number.isInteger(numero) ||
    numero < 0
  ) {

    return null;

  }

  return numero;

};


const numeroDecimal = valor => {

  if (
    valor === undefined ||
    valor === null ||
    valor === ""
  ) {

    return null;

  }

  const numero =
    Number(valor);

  if (
    !Number.isFinite(numero) ||
    numero < 0
  ) {

    return null;

  }

  return numero;

};


// ==================================================
// TIPOS PERMITIDOS
// ==================================================

const TIPOS_PLAN = [
  "psicologo",
  "clinica",
  "rh",
  "educativo",
  "independiente"
];


// ==================================================
// VALIDAR MASTER
// ==================================================

const usuarioEsMaster = req => {

  const usuario =
    req.user || {};

  const role =
    Number(
      usuario.role
    );

  const rol =
    normalizarTipo(
      usuario.rol
    );

  const tipoAdmin =
    normalizarTipo(
      usuario.tipo_admin
    );


  return (
    role === 1 &&
    rol === "admin" &&
    tipoAdmin === "master"
  );

};


// ==================================================
// VALIDAR ACCESO MASTER
// ==================================================

const validarMaster = (
  req,
  res
) => {

  if (
    !req.user
  ) {

    res
      .status(401)
      .json({
        success: false,
        code:
          "NO_AUTENTICADO",
        message:
          "Debes iniciar sesión."
      });

    return false;

  }


  if (
    !usuarioEsMaster(
      req
    )
  ) {

    res
      .status(403)
      .json({
        success: false,
        code:
          "SOLO_MASTER",
        message:
          "Esta función está disponible únicamente para el Administrador Master."
      });

    return false;

  }


  return true;

};


// ==================================================
// LISTAR PLANES
// GET /api/planes
// ==================================================

export const listarPlanes =
  async (
    req,
    res
  ) => {

    try {

      if (
        !validarMaster(
          req,
          res
        )
      ) {

        return;

      }


      const [
        planes
      ] =
        await pool.query(
          `
            SELECT
              p.id_plan,
              p.nombre,
              p.codigo,
              p.descripcion,
              p.tipo,

              p.precio_mensual,
              p.precio_anual,

              p.licencias_incluidas,
              p.permite_admin,
              p.periodo_prueba_dias,
              p.max_pacientes,

              p.destacado,
              p.activo,
              p.creado_en,

              COUNT(
                DISTINCT s.id_suscripcion
              ) AS total_suscripciones,

              COUNT(
                DISTINCT CASE
                  WHEN s.estado = 'activa'
                  THEN s.id_suscripcion
                END
              ) AS suscripciones_activas

            FROM planes p

            LEFT JOIN suscripciones s
              ON s.id_plan =
                 p.id_plan

            GROUP BY
              p.id_plan,
              p.nombre,
              p.codigo,
              p.descripcion,
              p.tipo,
              p.precio_mensual,
              p.precio_anual,
              p.licencias_incluidas,
              p.permite_admin,
              p.periodo_prueba_dias,
              p.max_pacientes,
              p.destacado,
              p.activo,
              p.creado_en

            ORDER BY
              p.activo DESC,
              p.tipo ASC,
              p.nombre ASC
          `
        );


      return res.json({
        success: true,
        total:
          planes.length,
        planes
      });

    }

    catch (
      error
    ) {

      console.error(
        "❌ Error listando planes:",
        error
      );


      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al obtener los planes."
        });

    }

  };


// ==================================================
// OBTENER PLAN
// GET /api/planes/:id
// ==================================================

export const obtenerPlan =
  async (
    req,
    res
  ) => {

    try {

      if (
        !validarMaster(
          req,
          res
        )
      ) {

        return;

      }


      const idPlan =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idPlan
        ) ||
        idPlan <= 0
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El id del plan no es válido."
          });

      }


      const [
        planes
      ] =
        await pool.query(
          `
            SELECT
              p.id_plan,
              p.nombre,
              p.codigo,
              p.descripcion,
              p.tipo,

              p.precio_mensual,
              p.precio_anual,

              p.licencias_incluidas,
              p.permite_admin,
              p.periodo_prueba_dias,
              p.max_pacientes,

              p.destacado,
              p.activo,
              p.creado_en,

              COUNT(
                DISTINCT s.id_suscripcion
              ) AS total_suscripciones,

              COUNT(
                DISTINCT CASE
                  WHEN s.estado = 'activa'
                  THEN s.id_suscripcion
                END
              ) AS suscripciones_activas,

              COUNT(
                DISTINCT CASE
                  WHEN s.estado = 'prueba'
                  THEN s.id_suscripcion
                END
              ) AS suscripciones_prueba,

              COUNT(
                DISTINCT CASE
                  WHEN s.estado = 'vencida'
                  THEN s.id_suscripcion
                END
              ) AS suscripciones_vencidas

            FROM planes p

            LEFT JOIN suscripciones s
              ON s.id_plan =
                 p.id_plan

            WHERE
              p.id_plan = ?

            GROUP BY
              p.id_plan,
              p.nombre,
              p.codigo,
              p.descripcion,
              p.tipo,
              p.precio_mensual,
              p.precio_anual,
              p.licencias_incluidas,
              p.permite_admin,
              p.periodo_prueba_dias,
              p.max_pacientes,
              p.destacado,
              p.activo,
              p.creado_en

            LIMIT 1
          `,
          [
            idPlan
          ]
        );


      if (
        !planes.length
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "El plan no existe."
          });

      }


      return res.json({
        success: true,
        plan:
          planes[0]
      });

    }

    catch (
      error
    ) {

      console.error(
        "❌ Error obteniendo plan:",
        error
      );


      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al obtener el plan."
        });

    }

  };


// ==================================================
// CREAR PLAN
// POST /api/planes
// ==================================================

export const crearPlan =
  async (
    req,
    res
  ) => {

    let connection;


    try {

      if (
        !validarMaster(
          req,
          res
        )
      ) {

        return;

      }


      const {
        nombre,
        codigo,
        descripcion,
        tipo,

        precio_mensual,
        precio_anual,

        licencias_incluidas,
        permite_admin,
        periodo_prueba_dias,
        max_pacientes,

        destacado,
        activo
      } =
        req.body || {};


      const nombreFinal =
        normalizarTexto(
          nombre
        );


      const codigoFinal =
        normalizarTexto(
          codigo
        )
          .toUpperCase()
          .replace(
            /\s+/g,
            "_"
          );


      const descripcionFinal =
        normalizarTexto(
          descripcion
        ) || null;


      const tipoFinal =
        normalizarTipo(
          tipo
        );


      if (
        !nombreFinal
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El nombre del plan es obligatorio."
          });

      }


      if (
        !codigoFinal
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El código del plan es obligatorio."
          });

      }


      if (
        !TIPOS_PLAN.includes(
          tipoFinal
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El tipo de plan no es válido.",
            tipos_permitidos:
              TIPOS_PLAN
          });

      }


      const precioMensual =
        numeroDecimal(
          precio_mensual
        );


      const precioAnual =
        numeroDecimal(
          precio_anual
        );


      if (
        precioMensual === null
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El precio mensual debe ser un número válido mayor o igual a 0."
          });

      }


      if (
        precioAnual === null
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El precio anual debe ser un número válido mayor o igual a 0."
          });

      }


      const licencias =
        numeroEntero(
          licencias_incluidas
        );


      if (
        licencias === null ||
        licencias <= 0
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Las licencias incluidas deben ser un número entero mayor a 0."
          });

      }


      const pruebaDias =
        numeroEntero(
          periodo_prueba_dias ??
          0
        );


      if (
        pruebaDias === null
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Los días de prueba no son válidos."
          });

      }


      let maxPacientesFinal =
        null;


      if (
        max_pacientes !== undefined &&
        max_pacientes !== null &&
        max_pacientes !== ""
      ) {

        maxPacientesFinal =
          numeroEntero(
            max_pacientes
          );


        if (
          maxPacientesFinal === null
        ) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "El máximo de pacientes no es válido."
            });

        }

      }


      const permiteAdminFinal =
        permite_admin === true ||
        Number(
          permite_admin
        ) === 1
          ? 1
          : 0;


      const destacadoFinal =
        destacado === true ||
        Number(
          destacado
        ) === 1
          ? 1
          : 0;


      const activoFinal =
        activo === false ||
        Number(
          activo
        ) === 0
          ? 0
          : 1;


      connection =
        await pool.getConnection();


      await connection.beginTransaction();


      const [
        existentes
      ] =
        await connection.query(
          `
            SELECT
              id_plan
            FROM planes
            WHERE
              UPPER(TRIM(codigo)) =
              UPPER(TRIM(?))
            LIMIT 1
            FOR UPDATE
          `,
          [
            codigoFinal
          ]
        );


      if (
        existentes.length
      ) {

        await connection.rollback();


        return res
          .status(409)
          .json({
            success: false,
            code:
              "CODIGO_PLAN_EXISTENTE",
            message:
              "Ya existe un plan con ese código."
          });

      }


      const [
        resultado
      ] =
        await connection.query(
          `
            INSERT INTO planes
            (
              nombre,
              codigo,
              descripcion,
              tipo,

              precio_mensual,
              precio_anual,

              licencias_incluidas,
              permite_admin,
              periodo_prueba_dias,
              max_pacientes,

              destacado,
              activo,
              creado_en
            )

            VALUES
            (
              ?, ?, ?, ?,
              ?, ?,
              ?, ?, ?, ?,
              ?, ?,
              NOW()
            )
          `,
          [
            nombreFinal,
            codigoFinal,
            descripcionFinal,
            tipoFinal,

            precioMensual,
            precioAnual,

            licencias,
            permiteAdminFinal,
            pruebaDias,
            maxPacientesFinal,

            destacadoFinal,
            activoFinal
          ]
        );


      await connection.commit();


      return res
        .status(201)
        .json({
          success: true,
          message:
            "Plan creado correctamente.",
          plan: {
            id_plan:
              resultado.insertId,

            nombre:
              nombreFinal,

            codigo:
              codigoFinal,

            descripcion:
              descripcionFinal,

            tipo:
              tipoFinal,

            precio_mensual:
              precioMensual,

            precio_anual:
              precioAnual,

            licencias_incluidas:
              licencias,

            permite_admin:
              permiteAdminFinal,

            periodo_prueba_dias:
              pruebaDias,

            max_pacientes:
              maxPacientesFinal,

            destacado:
              destacadoFinal,

            activo:
              activoFinal
          }
        });

    }

    catch (
      error
    ) {

      if (
        connection
      ) {

        try {

          await connection.rollback();

        }

        catch {}

      }


      console.error(
        "❌ Error creando plan:",
        error
      );


      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al crear el plan."
        });

    }

    finally {

      if (
        connection
      ) {

        connection.release();

      }

    }

  };


// ==================================================
// ACTUALIZAR PLAN
// PATCH /api/planes/:id
// ==================================================

export const actualizarPlan =
  async (
    req,
    res
  ) => {

    let connection;


    try {

      if (
        !validarMaster(
          req,
          res
        )
      ) {

        return;

      }


      const idPlan =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idPlan
        ) ||
        idPlan <= 0
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El id del plan no es válido."
          });

      }


      connection =
        await pool.getConnection();


      await connection.beginTransaction();


      const [
        planes
      ] =
        await connection.query(
          `
            SELECT
              *
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

        await connection.rollback();


        return res
          .status(404)
          .json({
            success: false,
            message:
              "El plan no existe."
          });

      }


      const actual =
        planes[0];


      const nombreFinal =
        req.body.nombre !== undefined
          ? normalizarTexto(
              req.body.nombre
            )
          : actual.nombre;


      const codigoFinal =
        req.body.codigo !== undefined
          ? normalizarTexto(
              req.body.codigo
            )
              .toUpperCase()
              .replace(
                /\s+/g,
                "_"
              )
          : actual.codigo;


      const descripcionFinal =
        req.body.descripcion !== undefined
          ? (
              normalizarTexto(
                req.body.descripcion
              ) || null
            )
          : actual.descripcion;


      const tipoFinal =
        req.body.tipo !== undefined
          ? normalizarTipo(
              req.body.tipo
            )
          : actual.tipo;


      if (
        !nombreFinal
      ) {

        await connection.rollback();


        return res
          .status(400)
          .json({
            success: false,
            message:
              "El nombre del plan no puede quedar vacío."
          });

      }


      if (
        !codigoFinal
      ) {

        await connection.rollback();


        return res
          .status(400)
          .json({
            success: false,
            message:
              "El código del plan no puede quedar vacío."
          });

      }


      if (
        !TIPOS_PLAN.includes(
          tipoFinal
        )
      ) {

        await connection.rollback();


        return res
          .status(400)
          .json({
            success: false,
            message:
              "El tipo de plan no es válido."
          });

      }


      let precioMensual =
        Number(
          actual.precio_mensual
        );


      if (
        req.body.precio_mensual !==
        undefined
      ) {

        precioMensual =
          numeroDecimal(
            req.body.precio_mensual
          );


        if (
          precioMensual === null
        ) {

          await connection.rollback();


          return res
            .status(400)
            .json({
              success: false,
              message:
                "El precio mensual no es válido."
            });

        }

      }


      let precioAnual =
        Number(
          actual.precio_anual
        );


      if (
        req.body.precio_anual !==
        undefined
      ) {

        precioAnual =
          numeroDecimal(
            req.body.precio_anual
          );


        if (
          precioAnual === null
        ) {

          await connection.rollback();


          return res
            .status(400)
            .json({
              success: false,
              message:
                "El precio anual no es válido."
            });

        }

      }


      let licencias =
        Number(
          actual.licencias_incluidas
        );


      if (
        req.body.licencias_incluidas !==
        undefined
      ) {

        licencias =
          numeroEntero(
            req.body
              .licencias_incluidas
          );


        if (
          licencias === null ||
          licencias <= 0
        ) {

          await connection.rollback();


          return res
            .status(400)
            .json({
              success: false,
              message:
                "Las licencias incluidas deben ser mayores a 0."
            });

        }

      }


      let pruebaDias =
        Number(
          actual.periodo_prueba_dias ||
          0
        );


      if (
        req.body.periodo_prueba_dias !==
        undefined
      ) {

        pruebaDias =
          numeroEntero(
            req.body
              .periodo_prueba_dias
          );


        if (
          pruebaDias === null
        ) {

          await connection.rollback();


          return res
            .status(400)
            .json({
              success: false,
              message:
                "Los días de prueba no son válidos."
            });

        }

      }


      let maxPacientesFinal =
        actual.max_pacientes;


      if (
        req.body.max_pacientes !==
        undefined
      ) {

        if (
          req.body.max_pacientes ===
            null ||
          req.body.max_pacientes ===
            ""
        ) {

          maxPacientesFinal =
            null;

        }

        else {

          maxPacientesFinal =
            numeroEntero(
              req.body
                .max_pacientes
            );


          if (
            maxPacientesFinal ===
            null
          ) {

            await connection.rollback();


            return res
              .status(400)
              .json({
                success: false,
                message:
                  "El máximo de pacientes no es válido."
              });

          }

        }

      }


      const permiteAdminFinal =
        req.body.permite_admin !==
        undefined
          ? (
              req.body.permite_admin ===
                true ||
              Number(
                req.body
                  .permite_admin
              ) === 1
                ? 1
                : 0
            )
          : Number(
              actual.permite_admin
            );


      const destacadoFinal =
        req.body.destacado !==
        undefined
          ? (
              req.body.destacado ===
                true ||
              Number(
                req.body.destacado
              ) === 1
                ? 1
                : 0
            )
          : Number(
              actual.destacado
            );


      const activoFinal =
        req.body.activo !==
        undefined
          ? (
              req.body.activo ===
                true ||
              Number(
                req.body.activo
              ) === 1
                ? 1
                : 0
            )
          : Number(
              actual.activo
            );


      const [
        codigoExistente
      ] =
        await connection.query(
          `
            SELECT
              id_plan
            FROM planes
            WHERE
              UPPER(TRIM(codigo)) =
              UPPER(TRIM(?))
              AND id_plan <> ?
            LIMIT 1
            FOR UPDATE
          `,
          [
            codigoFinal,
            idPlan
          ]
        );


      if (
        codigoExistente.length
      ) {

        await connection.rollback();


        return res
          .status(409)
          .json({
            success: false,
            code:
              "CODIGO_PLAN_EXISTENTE",
            message:
              "Ya existe otro plan con ese código."
          });

      }


      await connection.query(
        `
          UPDATE planes
          SET
            nombre = ?,
            codigo = ?,
            descripcion = ?,
            tipo = ?,

            precio_mensual = ?,
            precio_anual = ?,

            licencias_incluidas = ?,
            permite_admin = ?,
            periodo_prueba_dias = ?,
            max_pacientes = ?,

            destacado = ?,
            activo = ?

          WHERE
            id_plan = ?
        `,
        [
          nombreFinal,
          codigoFinal,
          descripcionFinal,
          tipoFinal,

          precioMensual,
          precioAnual,

          licencias,
          permiteAdminFinal,
          pruebaDias,
          maxPacientesFinal,

          destacadoFinal,
          activoFinal,

          idPlan
        ]
      );


      await connection.commit();


      return res.json({
        success: true,
        message:
          "Plan actualizado correctamente.",
        plan: {
          id_plan:
            idPlan,

          nombre:
            nombreFinal,

          codigo:
            codigoFinal,

          descripcion:
            descripcionFinal,

          tipo:
            tipoFinal,

          precio_mensual:
            precioMensual,

          precio_anual:
            precioAnual,

          licencias_incluidas:
            licencias,

          permite_admin:
            permiteAdminFinal,

          periodo_prueba_dias:
            pruebaDias,

          max_pacientes:
            maxPacientesFinal,

          destacado:
            destacadoFinal,

          activo:
            activoFinal
        }
      });

    }

    catch (
      error
    ) {

      if (
        connection
      ) {

        try {

          await connection.rollback();

        }

        catch {}

      }


      console.error(
        "❌ Error actualizando plan:",
        error
      );


      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al actualizar el plan."
        });

    }

    finally {

      if (
        connection
      ) {

        connection.release();

      }

    }

  };


// ==================================================
// ACTIVAR / DESACTIVAR PLAN
// PATCH /api/planes/:id/estado
// ==================================================

export const cambiarEstadoPlan =
  async (
    req,
    res
  ) => {

    try {

      if (
        !validarMaster(
          req,
          res
        )
      ) {

        return;

      }


      const idPlan =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idPlan
        ) ||
        idPlan <= 0
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "El id del plan no es válido."
          });

      }


      const activo =
        req.body?.activo;


      if (
        activo === undefined
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Debes indicar el estado activo."
          });

      }


      const estadoFinal =
        activo === true ||
        Number(
          activo
        ) === 1
          ? 1
          : 0;


      const [
        resultado
      ] =
        await pool.query(
          `
            UPDATE planes
            SET
              activo = ?
            WHERE
              id_plan = ?
          `,
          [
            estadoFinal,
            idPlan
          ]
        );


      if (
        resultado.affectedRows ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "El plan no existe."
          });

      }


      return res.json({
        success: true,
        message:
          estadoFinal
            ? "Plan activado correctamente."
            : "Plan desactivado correctamente.",
        id_plan:
          idPlan,
        activo:
          estadoFinal
      });

    }

    catch (
      error
    ) {

      console.error(
        "❌ Error cambiando estado del plan:",
        error
      );


      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al cambiar el estado del plan."
        });

    }

  };