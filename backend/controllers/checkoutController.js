// ============================================================
// backend/controllers/checkoutController.js
// ============================================================

import pool from "../config/database.js";


// ============================================================
// CREAR CHECKOUT / PAGO PENDIENTE
//
// POST /api/checkout
//
// Por ahora:
// - no cobra dinero real
// - crea registro en pagos
// - queda pendiente
//
// Después Mercado Pago / Stripe usará este mismo flujo.
// ============================================================

export async function crearCheckout(
  req,
  res
) {

  let connection;

  try {

    const {
      id_usuario,
      id_organizacion,
      id_plan,
      periodo = "mensual"
    } = req.body;


    // ========================================================
    // VALIDACIONES
    // ========================================================

    const idUsuario =
      Number(id_usuario);

    const idOrganizacion =
      Number(id_organizacion);

    const idPlan =
      Number(id_plan);


    if (
      !idUsuario ||
      !idOrganizacion ||
      !idPlan
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Faltan datos para crear el checkout"

        });

    }


    if (
      ![
        "mensual",
        "anual"
      ].includes(
        periodo
      )
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "El periodo seleccionado no es válido"

        });

    }


    // ========================================================
    // TRANSACCIÓN
    // ========================================================

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ========================================================
    // VALIDAR USUARIO
    // ========================================================

    const [
      usuarios
    ] =
      await connection
        .query(
          `
            SELECT

              id_usuario,
              nombre,
              correo,
              rol,
              area,
              id_organizacion,
              estado

            FROM usuarios

            WHERE
              id_usuario = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            idUsuario
          ]
        );


    if (
      !usuarios.length
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({

          success: false,

          message:
            "El usuario no existe"

        });

    }


    const usuario =
      usuarios[0];


    // ========================================================
    // DEBE SER INDEPENDIENTE
    // ========================================================

    if (
      String(
        usuario.rol ||
        ""
      )
        .trim()
        .toLowerCase() !==
      "independiente"
    ) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({

          success: false,

          message:
            "Este checkout es únicamente para cuentas independientes"

        });

    }


    // ========================================================
    // VALIDAR ORGANIZACIÓN DEL USUARIO
    // ========================================================

    if (
      Number(
        usuario.id_organizacion
      ) !==
      idOrganizacion
    ) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({

          success: false,

          message:
            "El usuario no pertenece a la organización indicada"

        });

    }


    // ========================================================
    // VALIDAR ORGANIZACIÓN
    // ========================================================

    const [
      organizaciones
    ] =
      await connection
        .query(
          `
            SELECT

              id_organizacion,
              nombre,
              tipo,
              estado

            FROM organizaciones

            WHERE
              id_organizacion = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            idOrganizacion
          ]
        );


    if (
      !organizaciones.length
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({

          success: false,

          message:
            "La organización no existe"

        });

    }


    const organizacion =
      organizaciones[0];


    if (
      String(
        organizacion.tipo ||
        ""
      )
        .trim()
        .toLowerCase() !==
      "independiente"
    ) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({

          success: false,

          message:
            "La organización no es de tipo independiente"

        });

    }


    // ========================================================
    // VALIDAR PLAN
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
              codigo,
              tipo,
              precio_mensual,
              precio_anual,
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

      await connection
        .rollback();


      return res
        .status(404)
        .json({

          success: false,

          message:
            "El plan no existe"

        });

    }


    const plan =
      planes[0];


    if (
      Number(
        plan.activo
      ) !== 1
    ) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({

          success: false,

          message:
            "El plan seleccionado no está activo"

        });

    }


    if (
      String(
        plan.tipo ||
        ""
      )
        .trim()
        .toLowerCase() !==
      "independiente"
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({

          success: false,

          message:
            "El plan seleccionado no corresponde a Independiente"

        });

    }


    // ========================================================
    // EVITAR DOBLE SUSCRIPCIÓN ACTIVA
    // ========================================================

    const [
      suscripcionesActivas
    ] =
      await connection
        .query(
          `
            SELECT
              id_suscripcion

            FROM suscripciones

            WHERE
              id_organizacion = ?

              AND estado IN
              (
                'activa',
                'prueba'
              )

            LIMIT 1
          `,
          [
            idOrganizacion
          ]
        );


    if (
      suscripcionesActivas.length
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success: false,

          code:
            "SUSCRIPCION_EXISTENTE",

          message:
            "Esta cuenta ya tiene una suscripción activa"

        });

    }


    // ========================================================
    // EVITAR DOS PAGOS PENDIENTES IGUALES
    // ========================================================

    const [
      pagosPendientes
    ] =
      await connection
        .query(
          `
            SELECT
              id_pago

            FROM pagos

            WHERE
              id_usuario = ?

              AND id_organizacion = ?

              AND id_plan = ?

              AND estado =
                  'pendiente'

            ORDER BY
              id_pago DESC

            LIMIT 1
          `,
          [
            idUsuario,
            idOrganizacion,
            idPlan
          ]
        );


    if (
      pagosPendientes.length
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success: false,

          code:
            "PAGO_PENDIENTE_EXISTENTE",

          message:
            "Ya existe un pago pendiente para este plan",

          id_pago:
            pagosPendientes[0]
              .id_pago

        });

    }


    // ========================================================
    // CALCULAR MONTO DESDE BD
    //
    // NUNCA aceptar el precio enviado por frontend.
    // ========================================================

    let monto = 0;


    if (
      periodo ===
      "anual"
    ) {

      monto =
        Number(
          plan.precio_anual ||
          0
        );

    } else {

      monto =
        Number(
          plan.precio_mensual ||
          0
        );

    }


    // ========================================================
    // CREAR PAGO PENDIENTE
    // ========================================================

    const [
      pagoInsertado
    ] =
      await connection
        .query(
          `
            INSERT INTO pagos
            (
              id_usuario,
              id_organizacion,
              id_plan,
              proveedor,
              referencia_externa,
              monto,
              moneda,
              periodo,
              estado,
              fecha_pago
            )

            VALUES
            (
              ?,
              ?,
              ?,
              'manual',
              NULL,
              ?,
              'MXN',
              ?,
              'pendiente',
              NULL
            )
          `,
          [
            idUsuario,
            idOrganizacion,
            idPlan,
            monto,
            periodo
          ]
        );


    const idPago =
      pagoInsertado
        .insertId;


    await connection
      .commit();


    // ========================================================
    // RESPUESTA
    // ========================================================

    return res
      .status(201)
      .json({

        success:
          true,

        message:
          "Checkout creado correctamente",

        pago: {

          id_pago:
            idPago,

          id_usuario:
            idUsuario,

          id_organizacion:
            idOrganizacion,

          id_plan:
            idPlan,

          plan:
            plan.nombre,

          periodo,

          monto,

          moneda:
            "MXN",

          proveedor:
            "manual",

          estado:
            "pendiente"

        },

        siguiente_paso:
          "pago"

      });


  } catch (
    error
  ) {

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      } catch {}

    }


    console.error(
      "❌ Error creando checkout:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error interno al crear checkout",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined

      });


  } finally {

    if (
      connection
    ) {

      connection
        .release();

    }

  }

}


// ============================================================
// APROBAR PAGO MANUALMENTE
//
// PATCH /api/checkout/:id/aprobar
//
// SOLO MASTER.
//
// Esto simula temporalmente lo que después hará
// el webhook de Mercado Pago / Stripe.
// ============================================================

export async function aprobarPago(
  req,
  res
) {

  let connection;


  try {

    // ========================================================
    // SOLO MASTER
    // ========================================================

    if (
      Number(
        req.user?.role
      ) !== 1 ||
      String(
        req.user?.tipo_admin ||
        ""
      )
        .trim()
        .toLowerCase() !==
      "master"
    ) {

      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "Solo el Administrador Master puede aprobar pagos manualmente"

        });

    }


    const idPago =
      Number(
        req.params.id
      );


    if (
      !idPago
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Pago inválido"

        });

    }


    // ========================================================
    // TRANSACCIÓN
    // ========================================================

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ========================================================
    // OBTENER PAGO
    // ========================================================

    const [
      pagos
    ] =
      await connection
        .query(
          `
            SELECT

              id_pago,
              id_usuario,
              id_organizacion,
              id_plan,
              monto,
              moneda,
              periodo,
              estado

            FROM pagos

            WHERE
              id_pago = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            idPago
          ]
        );


    if (
      !pagos.length
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "El pago no existe"

        });

    }


    const pago =
      pagos[0];


    // ========================================================
    // SI YA ESTÁ APROBADO
    // ========================================================

    if (
      pago.estado ===
      "aprobado"
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          code:
            "PAGO_YA_APROBADO",

          message:
            "Este pago ya fue aprobado"

        });

    }


    if (
      pago.estado !==
      "pendiente"
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          message:
            `No se puede aprobar un pago con estado ${pago.estado}`

        });

    }


    // ========================================================
    // OBTENER PLAN
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
            pago.id_plan
          ]
        );


    if (
      !planes.length
    ) {

      throw new Error(
        "El plan asociado al pago ya no existe"
      );

    }


    const plan =
      planes[0];


    if (
      plan.tipo !==
      "independiente"
    ) {

      throw new Error(
        "El pago no corresponde a un plan independiente"
      );

    }


    // ========================================================
    // VERIFICAR USUARIO / ORGANIZACIÓN
    // ========================================================

    const [
      usuarios
    ] =
      await connection
        .query(
          `
            SELECT

              id_usuario,
              rol,
              area,
              id_organizacion,
              estado

            FROM usuarios

            WHERE
              id_usuario = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            pago.id_usuario
          ]
        );


    if (
      !usuarios.length
    ) {

      throw new Error(
        "El usuario asociado al pago no existe"
      );

    }


    const usuario =
      usuarios[0];


    if (
      Number(
        usuario.id_organizacion
      ) !==
      Number(
        pago.id_organizacion
      )
    ) {

      throw new Error(
        "El usuario no corresponde a la organización del pago"
      );

    }


    // ========================================================
    // CALCULAR RENOVACIÓN
    // ========================================================

    let intervaloSQL;


    if (
      pago.periodo ===
      "anual"
    ) {

      intervaloSQL =
        "INTERVAL 1 YEAR";

    } else {

      intervaloSQL =
        "INTERVAL 1 MONTH";

    }


    // ========================================================
    // CREAR SUSCRIPCIÓN
    // ========================================================

    const [
      suscripcionInsertada
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
              CURDATE(),
              DATE_ADD(
                CURDATE(),
                ${intervaloSQL}
              ),
              DATE_ADD(
                CURDATE(),
                ${intervaloSQL}
              ),
              ?
            )
          `,
          [
            pago.id_organizacion,
            pago.id_plan,
            Number(
              plan.licencias_incluidas ||
              1
            )
          ]
        );


    const idSuscripcion =
      suscripcionInsertada
        .insertId;


    // ========================================================
    // INDEPENDIENTE = 1 LICENCIA PARA EL TITULAR
    // ========================================================

    const [
      licenciaInsertada
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
              fecha_asignacion,
              fecha_liberacion
            )

            VALUES
            (
              ?,
              ?,
              'independiente',
              'asignada',
              NOW(),
              NULL
            )
          `,
          [
            idSuscripcion,
            pago.id_usuario
          ]
        );


    const idLicencia =
      licenciaInsertada
        .insertId;


    // ========================================================
    // ACTIVAR ORGANIZACIÓN
    // ========================================================

    await connection
      .query(
        `
          UPDATE organizaciones

          SET
            estado =
              'activa'

          WHERE
            id_organizacion = ?
        `,
        [
          pago.id_organizacion
        ]
      );


    // ========================================================
    // ACTIVAR USUARIO
    // ========================================================

    await connection
      .query(
        `
          UPDATE usuarios

          SET
            estado =
              'activo'

          WHERE
            id_usuario = ?
        `,
        [
          pago.id_usuario
        ]
      );


    // ========================================================
    // APROBAR PAGO
    // ========================================================

    await connection
      .query(
        `
          UPDATE pagos

          SET
            estado =
              'aprobado',

            fecha_pago =
              NOW()

          WHERE
            id_pago = ?
        `,
        [
          idPago
        ]
      );


    // ========================================================
    // COMMIT
    // ========================================================

    await connection
      .commit();


    return res.json({

      success:
        true,

      message:
        "Pago aprobado y cuenta independiente activada correctamente",

      activacion: {

        id_pago:
          idPago,

        id_usuario:
          pago.id_usuario,

        id_organizacion:
          pago.id_organizacion,

        id_plan:
          pago.id_plan,

        id_suscripcion:
          idSuscripcion,

        id_licencia:
          idLicencia,

        estado_pago:
          "aprobado",

        estado_organizacion:
          "activa",

        estado_suscripcion:
          "activa"

      }

    });


  } catch (
    error
  ) {

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      } catch {}

    }


    console.error(
      "❌ Error aprobando pago:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error interno al aprobar el pago",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined

      });


  } finally {

    if (
      connection
    ) {

      connection
        .release();

    }

  }

}


// ============================================================
// CONSULTAR PAGO
//
// GET /api/checkout/:id
// ============================================================

export async function obtenerPago(
  req,
  res
) {

  try {

    const idPago =
      Number(
        req.params.id
      );


    if (
      !idPago
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Pago inválido"

        });

    }


    const [
      rows
    ] =
      await pool.query(
        `
          SELECT

            p.id_pago,
            p.id_usuario,
            p.id_organizacion,
            p.id_plan,

            p.proveedor,
            p.referencia_externa,
            p.monto,
            p.moneda,
            p.periodo,
            p.estado,
            p.fecha_pago,
            p.creado_en,

            pl.nombre AS plan,
            pl.tipo AS tipo_plan,

            o.nombre AS organizacion,
            o.estado AS estado_organizacion

          FROM pagos p

          INNER JOIN planes pl
            ON pl.id_plan =
               p.id_plan

          INNER JOIN organizaciones o
            ON o.id_organizacion =
               p.id_organizacion

          WHERE
            p.id_pago = ?

          LIMIT 1
        `,
        [
          idPago
        ]
      );


    if (
      !rows.length
    ) {

      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "Pago no encontrado"

        });

    }


    return res.json({

      success:
        true,

      pago:
        rows[0]

    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error consultando pago:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error interno al consultar el pago"

      });

  }

}