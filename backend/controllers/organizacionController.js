// backend/controllers/organizacionController.js

import pool from "../config/database.js";
import bcrypt from "bcrypt";


// ==================================================
// CONFIGURACIÓN GENERAL
// ==================================================

const DIAS_GRACIA = 3;


// ==================================================
// VALIDAR ADMINISTRADOR MASTER
// ==================================================

function esMaster(req) {

  const role =
    Number(
      req.user?.role
    );

  const tipoAdmin =
    req.user?.tipo_admin
      ? String(
          req.user.tipo_admin
        )
          .trim()
          .toLowerCase()
      : null;

  return (
    role === 1 &&
    tipoAdmin === "master"
  );
}


// ==================================================
// NORMALIZAR TIPO DE ORGANIZACIÓN
// ==================================================

function normalizarTipo(
  tipo
) {

  if (!tipo) {
    return null;
  }

  return String(
    tipo
  )
    .trim()
    .toLowerCase();
}


// ==================================================
// TIPO DE LICENCIA SEGÚN ORGANIZACIÓN
// ==================================================

function obtenerTipoLicencia(
  tipoOrganizacion
) {

  switch (
    tipoOrganizacion
  ) {

    case "clinica":
      return "psicologo";

    case "rh":
      return "rh";

    case "educativo":
      return "educativo";

    case "independiente":
      return "independiente";

    default:
      return null;
  }
}


// ==================================================
// FECHA YYYY-MM-DD
// ==================================================

function fechaSQL(
  fecha = new Date()
) {

  const anio =
    fecha.getFullYear();

  const mes =
    String(
      fecha.getMonth() + 1
    ).padStart(
      2,
      "0"
    );

  const dia =
    String(
      fecha.getDate()
    ).padStart(
      2,
      "0"
    );

  return `${anio}-${mes}-${dia}`;
}


// ==================================================
// SUMAR MESES
// ==================================================

function sumarMeses(
  fecha,
  meses = 1
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


// ==================================================
// SINCRONIZAR LICENCIAS
//
// - Si faltan licencias, las crea.
// - Si sobran, cancela únicamente disponibles.
// - NUNCA elimina licencias asignadas.
// ==================================================

async function sincronizarLicencias(
  connection,
  idSuscripcion,
  tipoLicencia,
  cantidadObjetivo
) {

  const objetivo =
    Number(
      cantidadObjetivo
    );

  if (
    !Number.isInteger(
      objetivo
    ) ||
    objetivo < 1
  ) {

    throw new Error(
      "La cantidad de licencias no es válida"
    );
  }


  const [
    rows
  ] =
    await connection.query(
      `
        SELECT

          COUNT(*) AS total,

          SUM(
            CASE
              WHEN estado = 'asignada'
              THEN 1
              ELSE 0
            END
          ) AS asignadas,

          SUM(
            CASE
              WHEN estado = 'disponible'
              THEN 1
              ELSE 0
            END
          ) AS disponibles

        FROM licencias

        WHERE
          id_suscripcion = ?
          AND estado <> 'cancelada'
      `,
      [
        idSuscripcion
      ]
    );


  const totalActual =
    Number(
      rows[0]?.total || 0
    );

  const asignadas =
    Number(
      rows[0]?.asignadas || 0
    );


  // ================================================
  // NO PERMITIR BAJAR DE LAS YA ASIGNADAS
  // ================================================

  if (
    asignadas >
    objetivo
  ) {

    const error =
      new Error(
        `No puedes reducir el plan a ${objetivo} licencias porque actualmente hay ${asignadas} asignadas.`
      );

    error.status =
      409;

    throw error;
  }


  // ================================================
  // CREAR LICENCIAS FALTANTES
  // ================================================

  if (
    totalActual <
    objetivo
  ) {

    const faltantes =
      objetivo -
      totalActual;


    for (
      let i = 0;
      i < faltantes;
      i++
    ) {

      await connection.query(
        `
          INSERT INTO licencias
          (
            id_suscripcion,
            id_usuario,
            tipo,
            estado
          )
          VALUES
          (
            ?,
            NULL,
            ?,
            'disponible'
          )
        `,
        [
          idSuscripcion,
          tipoLicencia
        ]
      );
    }
  }


  // ================================================
  // CANCELAR LICENCIAS SOBRANTES DISPONIBLES
  // ================================================

  if (
    totalActual >
    objetivo
  ) {

    const sobrantes =
      totalActual -
      objetivo;


    const [
      disponibles
    ] =
      await connection.query(
        `
          SELECT
            id_licencia

          FROM licencias

          WHERE
            id_suscripcion = ?
            AND estado = 'disponible'

          ORDER BY
            id_licencia DESC

          LIMIT ?
        `,
        [
          idSuscripcion,
          sobrantes
        ]
      );


    for (
      const licencia of
      disponibles
    ) {

      await connection.query(
        `
          UPDATE licencias

          SET
            estado = 'cancelada',
            fecha_liberacion = NOW()

          WHERE
            id_licencia = ?
        `,
        [
          licencia.id_licencia
        ]
      );
    }
  }
}


// ==================================================
// CREAR ORGANIZACIÓN
//
// MASTER:
//
// Organización
// ↓
// Suscripción
// ↓
// Licencias
// ↓
// Administrador principal
//
// IMPORTANTE:
// El administrador NO consume licencia.
//
// Independiente:
// No crea administrador.
// Después tendrá su registro independiente propio.
// ==================================================

export async function crearOrganizacion(
  req,
  res
) {

  let connection;

  try {

    // ================================================
    // SOLO MASTER
    // ================================================

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({
          success: false,

          message:
            "Acceso denegado. Solo el Administrador Master puede crear organizaciones."
        });
    }


    // ================================================
    // DATOS
    // ================================================

    const {

      nombre,
      nombre_comercial,
      responsable,
      correo,
      telefono,
      rfc,
      direccion,

      tipo,

      id_plan,

      licencias_totales,

      estado_suscripcion,

      fecha_inicio,
      proxima_renovacion,

      admin_nombre,
      admin_correo,
      admin_password,
      admin_telefono,
      admin_direccion

    } = req.body;


    // ================================================
    // VALIDAR ORGANIZACIÓN
    // ================================================

    const tipoOrganizacion =
      normalizarTipo(
        tipo
      );


    const tiposPermitidos = [
      "clinica",
      "rh",
      "educativo",
      "independiente"
    ];


    if (
      !nombre ||
      !tipoOrganizacion
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "Nombre y tipo de organización son obligatorios."
        });
    }


    if (
      !tiposPermitidos.includes(
        tipoOrganizacion
      )
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "El tipo de organización no es válido."
        });
    }


    if (
      !id_plan
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "Debes seleccionar un plan."
        });
    }


    // ================================================
    // ORGANIZACIONES NO INDEPENDIENTES
    // NECESITAN ADMINISTRADOR
    // ================================================

    const requiereAdministrador =
      tipoOrganizacion !==
      "independiente";


    if (
      requiereAdministrador &&
      (
        !admin_nombre ||
        !admin_correo ||
        !admin_password
      )
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "Nombre, correo y contraseña del administrador son obligatorios."
        });
    }


    if (
      requiereAdministrador &&
      String(
        admin_password
      ).length < 6
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "La contraseña del administrador debe tener al menos 6 caracteres."
        });
    }


    // ================================================
    // CONEXIÓN / TRANSACCIÓN
    // ================================================

    connection =
      await pool.getConnection();


    await connection
      .beginTransaction();


    // ================================================
    // VALIDAR PLAN
    // ================================================

    const [
      planes
    ] =
      await connection.query(
        `
          SELECT
            id_plan,
            nombre,
            tipo,
            licencias_incluidas,
            permite_admin,
            activo

          FROM planes

          WHERE
            id_plan = ?

          LIMIT 1
        `,
        [
          id_plan
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
            "El plan seleccionado no existe."
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
        .status(400)
        .json({
          success: false,

          message:
            "El plan seleccionado no está activo."
        });
    }


    // ================================================
    // VALIDAR COMPATIBILIDAD DEL PLAN
    // ================================================

    const tipoPlan =
      String(
        plan.tipo
      )
        .trim()
        .toLowerCase();


    let planCompatible =
      tipoPlan ===
      tipoOrganizacion;


    // Un independiente puede utilizar
    // posteriormente un plan tipo psicologo.

    if (
      tipoOrganizacion ===
        "independiente" &&
      tipoPlan ===
        "psicologo"
    ) {

      planCompatible =
        true;
    }


    if (
      !planCompatible
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({
          success: false,

          message:
            `El plan ${plan.nombre} no corresponde al tipo de organización ${tipoOrganizacion}.`
        });
    }


    // ================================================
    // DEFINIR LICENCIAS
    // ================================================

    const cantidadLicencias =
      licencias_totales !==
        undefined &&
      licencias_totales !==
        null
        ? Number(
            licencias_totales
          )
        : Number(
            plan.licencias_incluidas ||
            1
          );


    if (
      !Number.isInteger(
        cantidadLicencias
      ) ||
      cantidadLicencias < 1 ||
      cantidadLicencias > 10000
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({
          success: false,

          message:
            "La cantidad de licencias no es válida."
        });
    }


    // ================================================
    // VALIDAR CORREO ADMIN
    // ================================================

    const adminCorreoNormalizado =
      requiereAdministrador
        ? String(
            admin_correo
          )
            .trim()
            .toLowerCase()
        : null;


    if (
      requiereAdministrador
    ) {

      const [
        usuarioExistente
      ] =
        await connection.query(
          `
            SELECT
              id_usuario

            FROM usuarios

            WHERE
              correo = ?

            LIMIT 1
          `,
          [
            adminCorreoNormalizado
          ]
        );


      if (
        usuarioExistente.length
      ) {

        await connection
          .rollback();


        return res
          .status(409)
          .json({
            success: false,

            message:
              "Ya existe un usuario registrado con el correo del administrador."
          });
      }
    }


    // ================================================
    // CREAR ORGANIZACIÓN
    // ================================================

    const [
      organizacionInsert
    ] =
      await connection.query(
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
            estado
          )
          VALUES
          (
            ?, ?, ?, ?, ?, ?, ?, ?, 'activa'
          )
        `,
        [
          String(
            nombre
          ).trim(),

          nombre_comercial
            ? String(
                nombre_comercial
              ).trim()
            : null,

          responsable
            ? String(
                responsable
              ).trim()
            : null,

          correo
            ? String(
                correo
              )
                .trim()
                .toLowerCase()
            : null,

          telefono
            ? String(
                telefono
              ).trim()
            : null,

          rfc
            ? String(
                rfc
              )
                .trim()
                .toUpperCase()
            : null,

          direccion
            ? String(
                direccion
              ).trim()
            : null,

          tipoOrganizacion
        ]
      );


    const idOrganizacion =
      organizacionInsert
        .insertId;


    // ================================================
    // FECHAS DE SUSCRIPCIÓN
    // ================================================

    const hoy =
      new Date();


    const fechaInicioFinal =
      fecha_inicio ||
      fechaSQL(
        hoy
      );


    const proximaRenovacionFinal =
      proxima_renovacion ||
      fechaSQL(
        sumarMeses(
          hoy,
          1
        )
      );


    const estadoSuscripcion =
      [
        "prueba",
        "activa"
      ].includes(
        String(
          estado_suscripcion ||
          "activa"
        )
          .trim()
          .toLowerCase()
      )
        ? String(
            estado_suscripcion ||
            "activa"
          )
            .trim()
            .toLowerCase()
        : "activa";


    // ================================================
    // CREAR SUSCRIPCIÓN
    // ================================================

    const [
      suscripcionInsert
    ] =
      await connection.query(
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
            ?, ?, ?, ?, NULL, ?, ?
          )
        `,
        [
          idOrganizacion,
          id_plan,
          estadoSuscripcion,
          fechaInicioFinal,
          proximaRenovacionFinal,
          cantidadLicencias
        ]
      );


    const idSuscripcion =
      suscripcionInsert
        .insertId;


    // ================================================
    // CREAR LICENCIAS
    // ================================================

    const tipoLicencia =
      obtenerTipoLicencia(
        tipoOrganizacion
      );


    await sincronizarLicencias(
      connection,
      idSuscripcion,
      tipoLicencia,
      cantidadLicencias
    );


    // ================================================
    // CREAR ADMINISTRADOR PRINCIPAL
    //
    // NO CONSUME LICENCIA
    // ================================================

    let administrador =
      null;


    if (
      requiereAdministrador
    ) {

      const hashedPassword =
        await bcrypt.hash(
          String(
            admin_password
          ),
          10
        );


      const [
        adminInsert
      ] =
        await connection.query(
          `
            INSERT INTO usuarios
            (
              nombre,
              puesto,
              telefono,
              direccion,
              correo,
              password,
              rol,
              tipo_admin,
              area,
              id_admin_padre,
              id_organizacion
            )
            VALUES
            (
              ?, ?, ?, ?, ?, ?,
              'admin',
              'normal',
              ?,
              ?,
              ?
            )
          `,
          [
            String(
              admin_nombre
            ).trim(),

            "Administrador",

            admin_telefono
              ? String(
                  admin_telefono
                ).trim()
              : null,

            admin_direccion
              ? String(
                  admin_direccion
                ).trim()
              : null,

            adminCorreoNormalizado,

            hashedPassword,

            tipoOrganizacion,

            req.user.id_usuario,

            idOrganizacion
          ]
        );


      administrador = {
        id_usuario:
          adminInsert.insertId,

        nombre:
          String(
            admin_nombre
          ).trim(),

        correo:
          adminCorreoNormalizado,

        rol:
          "admin",

        tipo_admin:
          "normal",

        area:
          tipoOrganizacion,

        id_organizacion:
          idOrganizacion
      };
    }


    // ================================================
    // CONFIRMAR
    // ================================================

    await connection
      .commit();


    return res
      .status(201)
      .json({

        success: true,

        message:
          "Organización creada correctamente.",

        organizacion: {

          id_organizacion:
            idOrganizacion,

          nombre:
            String(
              nombre
            ).trim(),

          tipo:
            tipoOrganizacion,

          estado:
            "activa"
        },

        suscripcion: {

          id_suscripcion:
            idSuscripcion,

          id_plan:
            Number(
              id_plan
            ),

          plan:
            plan.nombre,

          estado:
            estadoSuscripcion,

          licencias_totales:
            cantidadLicencias,

          fecha_inicio:
            fechaInicioFinal,

          proxima_renovacion:
            proximaRenovacionFinal
        },

        administrador
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
      "❌ Error creando organización:",
      error
    );


    return res
      .status(
        error.status ||
        500
      )
      .json({

        success: false,

        message:
          error.message ||
          "Error interno al crear la organización."
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


// ==================================================
// LISTAR ORGANIZACIONES
//
// SOLO MASTER
// ==================================================

export async function listarOrganizaciones(
  req,
  res
) {

  try {

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({
          success: false,
          message:
            "Acceso denegado."
        });
    }


    const [
      rows
    ] =
      await pool.query(
        `
          SELECT

            o.id_organizacion,
            o.nombre,
            o.nombre_comercial,
            o.responsable,
            o.correo,
            o.telefono,
            o.rfc,
            o.direccion,
            o.tipo,
            o.estado,
            o.creado_en,

            s.id_suscripcion,
            s.estado
              AS estado_suscripcion,

            s.fecha_inicio,
            s.fecha_fin,
            s.proxima_renovacion,
            s.licencias_totales,

            p.id_plan,
            p.nombre
              AS plan_nombre,

            (
              SELECT COUNT(*)

              FROM licencias l

              WHERE
                l.id_suscripcion =
                s.id_suscripcion

                AND l.estado =
                'asignada'
            )
              AS licencias_usadas,

            (
              SELECT COUNT(*)

              FROM licencias l

              WHERE
                l.id_suscripcion =
                s.id_suscripcion

                AND l.estado =
                'disponible'
            )
              AS licencias_disponibles,

            (
              SELECT COUNT(*)

              FROM usuarios u

              WHERE
                u.id_organizacion =
                o.id_organizacion
            )
              AS total_usuarios

          FROM organizaciones o

          LEFT JOIN suscripciones s
            ON s.id_suscripcion =
            (
              SELECT
                s2.id_suscripcion

              FROM suscripciones s2

              WHERE
                s2.id_organizacion =
                o.id_organizacion

              ORDER BY
                s2.id_suscripcion DESC

              LIMIT 1
            )

          LEFT JOIN planes p
            ON p.id_plan =
            s.id_plan

          ORDER BY
            o.id_organizacion DESC
        `
      );


    return res.json({
      success: true,

      organizaciones:
        rows || []
    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error listando organizaciones:",
      error
    );


    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error al obtener las organizaciones."
      });
  }
}


// ==================================================
// OBTENER UNA ORGANIZACIÓN
//
// SOLO MASTER
//
// Devuelve:
// - organización
// - suscripción actual
// - historial de suscripciones
// - usuarios
// - licencias detalladas
// - pagos
// - diagnóstico comercial
// ==================================================

export async function obtenerOrganizacion(
  req,
  res
) {

  try {

    // ================================================
    // SOLO MASTER
    // ================================================

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({
          success: false,
          message:
            "Acceso denegado."
        });

    }


    // ================================================
    // ID ORGANIZACIÓN
    // ================================================

    const idOrganizacion =
      Number(
        req.params.id
      );


    if (
      !idOrganizacion
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "ID de organización inválido."
        });

    }


    // ================================================
    // ORGANIZACIÓN
    // ================================================

    const [
      organizaciones
    ] =
      await pool.query(
        `
          SELECT

            id_organizacion,
            nombre,
            nombre_comercial,
            responsable,
            correo,
            telefono,
            rfc,
            direccion,
            logo_url,
            tipo,
            estado,
            creado_en,
            actualizado_en

          FROM organizaciones

          WHERE
            id_organizacion = ?

          LIMIT 1
        `,
        [
          idOrganizacion
        ]
      );


    if (
      !organizaciones.length
    ) {

      return res
        .status(404)
        .json({
          success: false,

          message:
            "Organización no encontrada."
        });

    }


    const organizacion =
      organizaciones[0];


    // ================================================
    // SUSCRIPCIONES
    // MÁS RECIENTE PRIMERO
    // ================================================

    const [
      suscripciones
    ] =
      await pool.query(
        `
          SELECT

            s.id_suscripcion,
            s.id_organizacion,
            s.id_plan,
            s.estado,
            s.fecha_inicio,
            s.fecha_fin,
            s.proxima_renovacion,
            s.licencias_totales,

            s.origen_suscripcion,
            s.motivo_beneficio,
            s.otorgado_por,
            s.fecha_otorgamiento,

            s.creado_en,

            p.nombre
              AS plan_nombre,

            p.codigo
              AS plan_codigo,

            p.tipo
              AS plan_tipo,

            p.precio_mensual,
            p.precio_anual,

            p.licencias_incluidas,

            p.permite_admin,

            p.periodo_prueba_dias,

            p.max_pacientes

          FROM suscripciones s

          INNER JOIN planes p
            ON p.id_plan =
               s.id_plan

          WHERE
            s.id_organizacion = ?

          ORDER BY
            s.id_suscripcion DESC
        `,
        [
          idOrganizacion
        ]
      );


    const suscripcionActual =
      suscripciones.length
        ? suscripciones[0]
        : null;


    // ================================================
    // USUARIOS
    // ================================================

    const [
      usuarios
    ] =
      await pool.query(
        `
          SELECT

            u.id_usuario,
            u.nombre,
            u.puesto,
            u.telefono,
            u.direccion,
            u.correo,
            u.matricula,
            u.rol,
            u.tipo_admin,
            u.area,
            u.id_admin_padre,
            u.id_organizacion,
            u.estado,
            u.debe_cambiar_password,
            u.creado_en

          FROM usuarios u

          WHERE
            u.id_organizacion = ?

          ORDER BY

            CASE
              WHEN u.rol = 'admin'
              THEN 0
              ELSE 1
            END,

            u.creado_en ASC
        `,
        [
          idOrganizacion
        ]
      );


    // ================================================
    // LICENCIAS DE SUSCRIPCIÓN ACTUAL
    // ================================================

    let licencias = [];


    if (
      suscripcionActual
    ) {

      const [
        licenciasRows
      ] =
        await pool.query(
          `
            SELECT

              l.id_licencia,
              l.id_suscripcion,
              l.id_usuario,
              l.tipo,
              l.estado,
              l.fecha_asignacion,
              l.fecha_liberacion,
              l.creado_en,

              u.nombre
                AS usuario_nombre,

              u.correo
                AS usuario_correo,

              u.matricula
                AS usuario_matricula,

              u.rol
                AS usuario_rol,

              u.estado
                AS usuario_estado

            FROM licencias l

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 l.id_usuario

            WHERE
              l.id_suscripcion = ?

            ORDER BY
              l.id_licencia ASC
          `,
          [
            suscripcionActual
              .id_suscripcion
          ]
        );


      licencias =
        licenciasRows || [];

    }


    // ================================================
    // PAGOS
    // ================================================

    const [
      pagos
    ] =
      await pool.query(
        `
          SELECT

            pg.id_pago,
            pg.id_usuario,
            pg.id_organizacion,
            pg.id_plan,
            pg.proveedor,
            pg.referencia_externa,
            pg.monto,
            pg.moneda,
            pg.periodo,
            pg.estado,
            pg.fecha_pago,
            pg.creado_en,
            pg.actualizado_en,

            p.nombre
              AS plan_nombre,

            u.nombre
              AS usuario_nombre

          FROM pagos pg

          LEFT JOIN planes p
            ON p.id_plan =
               pg.id_plan

          LEFT JOIN usuarios u
            ON u.id_usuario =
               pg.id_usuario

          WHERE
            pg.id_organizacion = ?

          ORDER BY
            pg.id_pago DESC
        `,
        [
          idOrganizacion
        ]
      );


    // ================================================
    // CONTEO DE LICENCIAS
    // ================================================

    const licenciasAsignadas =
      licencias.filter(
        licencia =>
          licencia.estado ===
          "asignada"
      ).length;


    const licenciasDisponibles =
      licencias.filter(
        licencia =>
          licencia.estado ===
          "disponible"
      ).length;


    const licenciasSuspendidas =
      licencias.filter(
        licencia =>
          licencia.estado ===
          "suspendida"
      ).length;


    const licenciasCanceladas =
      licencias.filter(
        licencia =>
          licencia.estado ===
          "cancelada"
      ).length;


    // ================================================
    // ADMINISTRADORES
    // ================================================

    const administradores =
      usuarios.filter(
        usuario =>
          usuario.rol ===
          "admin"
      );


    const administradoresActivos =
      administradores.filter(
        usuario =>
          usuario.estado ===
          "activo"
      );


    // ================================================
    // DIAGNÓSTICO
    // ================================================

    const problemas = [];


    if (
      !suscripcionActual
    ) {

      problemas.push({
        codigo:
          "SIN_SUSCRIPCION",

        nivel:
          "error",

        mensaje:
          "La organización no tiene una suscripción."
      });

    }


    if (
      suscripcionActual
    ) {

      if (
        organizacion.estado ===
          "activa" &&
        ![
          "activa",
          "prueba"
        ].includes(
          suscripcionActual.estado
        )
      ) {

        problemas.push({
          codigo:
            "ORGANIZACION_ACTIVA_SUSCRIPCION_INACTIVA",

          nivel:
            "advertencia",

          mensaje:
            "La organización está activa pero su suscripción no está activa."
        });

      }


      if (
        organizacion.estado ===
          "suspendida" &&
        [
          "activa",
          "prueba"
        ].includes(
          suscripcionActual.estado
        )
      ) {

        problemas.push({
          codigo:
            "ORGANIZACION_SUSPENDIDA_SUSCRIPCION_ACTIVA",

          nivel:
            "advertencia",

          mensaje:
            "La organización está suspendida pero su suscripción continúa activa."
        });

      }


      const totalLicenciasBD =
        licencias.filter(
          licencia =>
            licencia.estado !==
            "cancelada"
        ).length;


      if (
        Number(
          suscripcionActual
            .licencias_totales
        ) !==
        totalLicenciasBD
      ) {

        problemas.push({
          codigo:
            "LICENCIAS_DESINCRONIZADAS",

          nivel:
            "advertencia",

          mensaje:
            `La suscripción indica ${
              suscripcionActual
                .licencias_totales
            } licencias, pero existen ${
              totalLicenciasBD
            } licencias vigentes.`
        });

      }

    }


    // ================================================
    // ADMIN SEGÚN TIPO
    // ================================================

    if (
      organizacion.tipo !==
      "independiente"
    ) {

      if (
        administradores.length ===
        0
      ) {

        problemas.push({
          codigo:
            "SIN_ADMINISTRADOR",

          nivel:
            "error",

          mensaje:
            "La organización no tiene un administrador registrado."
        });

      }


      if (
        administradores.length >
          0 &&
        administradoresActivos
          .length === 0
      ) {

        problemas.push({
          codigo:
            "ADMINISTRADOR_INACTIVO",

          nivel:
            "advertencia",

          mensaje:
            "La organización tiene administrador, pero ninguno se encuentra activo."
        });

      }

    }


    // ================================================
    // USUARIOS CON LICENCIA SUSPENDIDA
    // ================================================

    for (
      const licencia of
      licencias
    ) {

      if (
        licencia.estado ===
          "suspendida" &&
        licencia.id_usuario
      ) {

        problemas.push({
          codigo:
            "USUARIO_LICENCIA_SUSPENDIDA",

          nivel:
            "advertencia",

          id_usuario:
            licencia.id_usuario,

          id_licencia:
            licencia.id_licencia,

          mensaje:
            `El usuario ${
              licencia.usuario_nombre ||
              licencia.id_usuario
            } tiene una licencia suspendida.`
        });

      }

    }


    // ================================================
    // OBJETO COMPATIBLE CON FRONTEND ACTUAL
    //
    // IMPORTANTE:
    // AdminComercial actualmente usa
    // detalle.organizacion.
    //
    // Por eso incluimos también aquí los datos
    // principales de la suscripción.
    // ================================================

    const organizacionCompleta = {

      ...organizacion,


      // Suscripción actual
      suscripcion:
        suscripcionActual,


      // Compatibilidad con frontend actual
      id_suscripcion:
        suscripcionActual
          ?.id_suscripcion ??
        null,

      id_plan:
        suscripcionActual
          ?.id_plan ??
        null,

      plan:
        suscripcionActual
          ?.plan_nombre ??
        null,

      plan_nombre:
        suscripcionActual
          ?.plan_nombre ??
        null,

      estado_suscripcion:
        suscripcionActual
          ?.estado ??
        null,

      fecha_inicio:
        suscripcionActual
          ?.fecha_inicio ??
        null,

      fecha_fin:
        suscripcionActual
          ?.fecha_fin ??
        null,

      proxima_renovacion:
        suscripcionActual
          ?.proxima_renovacion ??
        null,

      licencias_totales:
        suscripcionActual
          ?.licencias_totales ??
        0,


      // Conteo
      licencias_usadas:
        licenciasAsignadas,

      licencias_disponibles:
        licenciasDisponibles,

      licencias_suspendidas:
        licenciasSuspendidas,

      licencias_canceladas:
        licenciasCanceladas,


      // Soporte
      total_usuarios:
        usuarios.length,

      total_pagos:
        pagos.length,

      problemas_detectados:
        problemas.length

    };


    // ================================================
    // RESPUESTA
    // ================================================

    return res.json({

      success: true,


      organizacion:
        organizacionCompleta,


      // Suscripción actual
      suscripcion:
        suscripcionActual,


      // Historial
      suscripciones:
        suscripciones || [],


      // Usuarios
      usuarios:
        usuarios || [],


      // Licencias individuales
      licencias:
        licencias || [],


      resumen_licencias: {

        totales:
          Number(
            suscripcionActual
              ?.licencias_totales ||
            0
          ),

        usadas:
          licenciasAsignadas,

        disponibles:
          licenciasDisponibles,

        suspendidas:
          licenciasSuspendidas,

        canceladas:
          licenciasCanceladas

      },


      // Pagos
      pagos:
        pagos || [],


      // Diagnóstico
      diagnostico: {

        correcto:
          problemas.length ===
          0,

        total_problemas:
          problemas.length,

        problemas

      }

    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error obteniendo organización:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error al obtener la organización.",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined

      });

  }

}


// ==================================================
// OBTENER ESTADO DE LICENCIAS
//
// MASTER:
// puede consultar cualquier organización.
//
// ADMIN NORMAL:
// solamente su organización.
// ==================================================

export async function obtenerEstadoLicencias(
  req,
  res
) {

  try {

    const idOrganizacionParametro =
      Number(
        req.params.id
      );


    let idOrganizacion =
      idOrganizacionParametro;


    // ================================================
    // ADMIN NORMAL
    // ================================================

    if (
      Number(
        req.user?.role
      ) === 1 &&
      String(
        req.user?.tipo_admin ||
        ""
      )
        .trim()
        .toLowerCase() ===
        "normal"
    ) {

      idOrganizacion =
        Number(
          req.user
            ?.id_organizacion
        );
    }


    // ================================================
    // VALIDAR ADMIN
    // ================================================

    if (
      Number(
        req.user?.role
      ) !== 1
    ) {

      return res
        .status(403)
        .json({
          success: false,

          message:
            "Acceso denegado."
        });
    }


    if (
      !idOrganizacion
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "No se pudo identificar la organización."
        });
    }


    const [
      rows
    ] =
      await pool.query(
        `
          SELECT

            s.id_suscripcion,
            s.id_organizacion,
            s.estado
              AS estado_suscripcion,

            s.fecha_inicio,
            s.fecha_fin,
            s.proxima_renovacion,

            s.licencias_totales,

            p.nombre
              AS plan_nombre,

            p.tipo
              AS plan_tipo,

            SUM(
              CASE
                WHEN l.estado = 'asignada'
                THEN 1
                ELSE 0
              END
            )
              AS licencias_usadas,

            SUM(
              CASE
                WHEN l.estado = 'disponible'
                THEN 1
                ELSE 0
              END
            )
              AS licencias_disponibles,

            SUM(
              CASE
                WHEN l.estado = 'suspendida'
                THEN 1
                ELSE 0
              END
            )
              AS licencias_suspendidas

          FROM suscripciones s

          INNER JOIN planes p
            ON p.id_plan =
            s.id_plan

          LEFT JOIN licencias l
            ON l.id_suscripcion =
            s.id_suscripcion

            AND l.estado <>
            'cancelada'

          WHERE
            s.id_organizacion = ?

          GROUP BY
            s.id_suscripcion

          ORDER BY
            s.id_suscripcion DESC

          LIMIT 1
        `,
        [
          idOrganizacion
        ]
      );


    if (
      !rows.length
    ) {

      return res
        .status(404)
        .json({
          success: false,

          message:
            "La organización no tiene una suscripción."
        });
    }


    const estado =
      rows[0];


    return res.json({

      success: true,

      licencias: {

        ...estado,

        licencias_usadas:
          Number(
            estado
              .licencias_usadas ||
            0
          ),

        licencias_disponibles:
          Number(
            estado
              .licencias_disponibles ||
            0
          ),

        licencias_suspendidas:
          Number(
            estado
              .licencias_suspendidas ||
            0
          )
      }
    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error obteniendo licencias:",
      error
    );


    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error al consultar las licencias."
      });
  }
}


// ==================================================
// ACTIVAR SUSCRIPCIÓN MANUALMENTE
//
// SOLO MASTER.
//
// Útil para:
// - convenios
// - pruebas
// - cortesías
// - activación manual
//
// Los pagos automáticos reutilizarán después
// esta misma lógica.
// ==================================================

export async function activarSuscripcion(
  req,
  res
) {

  let connection;

  try {

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({
          success: false,

          message:
            "Solo el Master puede activar una suscripción manualmente."
        });
    }


    const idOrganizacion =
      Number(
        req.params.id
      );


    connection =
      await pool.getConnection();


    await connection
      .beginTransaction();


    const [
      suscripciones
    ] =
      await connection.query(
        `
          SELECT

            s.*,

            o.tipo
              AS tipo_organizacion

          FROM suscripciones s

          INNER JOIN organizaciones o
            ON o.id_organizacion =
            s.id_organizacion

          WHERE
            s.id_organizacion = ?

          ORDER BY
            s.id_suscripcion DESC

          LIMIT 1

          FOR UPDATE
        `,
        [
          idOrganizacion
        ]
      );


    if (
      !suscripciones.length
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({
          success: false,

          message:
            "No existe una suscripción para esta organización."
        });
    }


    const suscripcion =
      suscripciones[0];


    const nuevasLicencias =
      req.body
        ?.licencias_totales !==
        undefined
        ? Number(
            req.body
              .licencias_totales
          )
        : Number(
            suscripcion
              .licencias_totales
          );


    const meses =
      Number(
        req.body?.meses ||
        1
      );


    const hoy =
      new Date();


    const siguienteRenovacion =
      fechaSQL(
        sumarMeses(
          hoy,
          meses
        )
      );


    await connection.query(
      `
        UPDATE suscripciones

        SET
          estado = 'activa',
          fecha_fin = NULL,
          proxima_renovacion = ?,
          licencias_totales = ?

        WHERE
          id_suscripcion = ?
      `,
      [
        siguienteRenovacion,
        nuevasLicencias,
        suscripcion.id_suscripcion
      ]
    );


    await connection.query(
      `
        UPDATE organizaciones

        SET
          estado = 'activa'

        WHERE
          id_organizacion = ?
      `,
      [
        idOrganizacion
      ]
    );


    await sincronizarLicencias(
      connection,
      suscripcion.id_suscripcion,
      obtenerTipoLicencia(
        suscripcion.tipo_organizacion
      ),
      nuevasLicencias
    );


    await connection
      .commit();


    return res.json({

      success: true,

      message:
        "Suscripción activada correctamente.",

      estado:
        "activa",

      proxima_renovacion:
        siguienteRenovacion,

      licencias_totales:
        nuevasLicencias
    });


  } catch (
    error
  ) {

    if (
      connection
    ) {

      try {
        await connection.rollback();
      } catch {}
    }


    console.error(
      "❌ Error activando suscripción:",
      error
    );


    return res
      .status(
        error.status ||
        500
      )
      .json({

        success: false,

        message:
          error.message ||
          "Error al activar la suscripción."
      });


  } finally {

    if (
      connection
    ) {
      connection.release();
    }
  }
}


// ==================================================
// RENOVAR SUSCRIPCIÓN
//
// Por ahora puede usarla MASTER.
//
// Más adelante el webhook de pago podrá llamar
// la misma lógica automáticamente.
//
// Ejemplo:
// meses = 1
// meses = 12
// ==================================================

export async function renovarSuscripcion(
  req,
  res
) {

  let connection;

  try {

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({
          success: false,

          message:
            "Solo el Master puede renovar manualmente una suscripción."
        });
    }


    const idOrganizacion =
      Number(
        req.params.id
      );


    const meses =
      Number(
        req.body?.meses ||
        1
      );


    if (
      !Number.isInteger(
        meses
      ) ||
      meses < 1 ||
      meses > 36
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "El número de meses no es válido."
        });
    }


    connection =
      await pool.getConnection();


    await connection
      .beginTransaction();


    const [
      rows
    ] =
      await connection.query(
        `
          SELECT

            s.*,

            o.tipo
              AS tipo_organizacion

          FROM suscripciones s

          INNER JOIN organizaciones o
            ON o.id_organizacion =
            s.id_organizacion

          WHERE
            s.id_organizacion = ?

          ORDER BY
            s.id_suscripcion DESC

          LIMIT 1

          FOR UPDATE
        `,
        [
          idOrganizacion
        ]
      );


    if (
      !rows.length
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({
          success: false,

          message:
            "Suscripción no encontrada."
        });
    }


    const suscripcion =
      rows[0];


    // ================================================
    // PARTIR DE LA FECHA ACTUAL O RENOVACIÓN
    // ================================================

    const hoy =
      new Date();


    let base =
      hoy;


    if (
      suscripcion
        .proxima_renovacion
    ) {

      const renovacionActual =
        new Date(
          suscripcion
            .proxima_renovacion
        );


      if (
        renovacionActual >
        hoy
      ) {

        base =
          renovacionActual;
      }
    }


    const nuevaRenovacion =
      fechaSQL(
        sumarMeses(
          base,
          meses
        )
      );


    const licenciasTotales =
      req.body
        ?.licencias_totales !==
        undefined
        ? Number(
            req.body
              .licencias_totales
          )
        : Number(
            suscripcion
              .licencias_totales
          );


    await sincronizarLicencias(
      connection,
      suscripcion.id_suscripcion,
      obtenerTipoLicencia(
        suscripcion
          .tipo_organizacion
      ),
      licenciasTotales
    );


    await connection.query(
      `
        UPDATE suscripciones

        SET
          estado = 'activa',
          fecha_fin = NULL,
          proxima_renovacion = ?,
          licencias_totales = ?

        WHERE
          id_suscripcion = ?
      `,
      [
        nuevaRenovacion,
        licenciasTotales,
        suscripcion
          .id_suscripcion
      ]
    );


    await connection.query(
      `
        UPDATE organizaciones

        SET
          estado = 'activa'

        WHERE
          id_organizacion = ?
      `,
      [
        idOrganizacion
      ]
    );


    await connection
      .commit();


    return res.json({

      success: true,

      message:
        "Suscripción renovada correctamente.",

      estado:
        "activa",

      proxima_renovacion:
        nuevaRenovacion,

      licencias_totales:
        licenciasTotales
    });


  } catch (
    error
  ) {

    if (
      connection
    ) {

      try {
        await connection.rollback();
      } catch {}
    }


    console.error(
      "❌ Error renovando suscripción:",
      error
    );


    return res
      .status(
        error.status ||
        500
      )
      .json({

        success: false,

        message:
          error.message ||
          "Error al renovar la suscripción."
      });


  } finally {

    if (
      connection
    ) {
      connection.release();
    }
  }
}

// ==================================================
// AJUSTAR LICENCIAS DE UNA ORGANIZACIÓN
//
// SOLO MASTER
//
// Permite:
// - aumentar licencias
// - reducir licencias disponibles
//
// NO:
// - renueva suscripción
// - modifica fecha de vencimiento
// - elimina licencias asignadas
// ==================================================

export async function ajustarLicenciasOrganizacion(
  req,
  res
) {

  let connection;

  try {

    // ================================================
    // SOLO MASTER
    // ================================================

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({

          success: false,

          message:
            "Solo el Administrador Master puede modificar licencias."

        });

    }


    // ================================================
    // DATOS
    // ================================================

    const idOrganizacion =
      Number(
        req.params.id
      );


    const licenciasTotales =
      Number(
        req.body
          ?.licencias_totales
      );


    if (
      !idOrganizacion
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "ID de organización inválido."

        });

    }


    if (
      !Number.isInteger(
        licenciasTotales
      ) ||
      licenciasTotales < 1 ||
      licenciasTotales > 10000
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "La cantidad de licencias no es válida."

        });

    }


    // ================================================
    // TRANSACCIÓN
    // ================================================

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ================================================
    // SUSCRIPCIÓN ACTUAL
    // ================================================

    const [
      rows
    ] =
      await connection
        .query(
          `
            SELECT

              s.id_suscripcion,
              s.id_organizacion,
              s.id_plan,
              s.estado,
              s.licencias_totales,

              o.tipo
                AS tipo_organizacion

            FROM suscripciones s

            INNER JOIN organizaciones o
              ON o.id_organizacion =
                 s.id_organizacion

            WHERE
              s.id_organizacion = ?

            ORDER BY
              s.id_suscripcion DESC

            LIMIT 1

            FOR UPDATE
          `,
          [
            idOrganizacion
          ]
        );


    if (
      !rows.length
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({

          success: false,

          message:
            "La organización no tiene una suscripción."

        });

    }


    const suscripcion =
      rows[0];


    // ================================================
    // TIPO DE LICENCIA
    // ================================================

    const tipoLicencia =
      obtenerTipoLicencia(
        suscripcion
          .tipo_organizacion
      );


    if (
      !tipoLicencia
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({

          success: false,

          message:
            "No se pudo determinar el tipo de licencia."

        });

    }


    // ================================================
    // SINCRONIZAR
    //
    // Esta función ya evita reducir
    // por debajo de las asignadas.
    // ================================================

    await sincronizarLicencias(
      connection,
      suscripcion
        .id_suscripcion,
      tipoLicencia,
      licenciasTotales
    );


    // ================================================
    // ACTUALIZAR SUSCRIPCIÓN
    // ================================================

    await connection
      .query(
        `
          UPDATE suscripciones

          SET
            licencias_totales = ?

          WHERE
            id_suscripcion = ?
        `,
        [
          licenciasTotales,
          suscripcion
            .id_suscripcion
        ]
      );


    // ================================================
    // CONTAR RESULTADO
    // ================================================

    const [
      estadoLicencias
    ] =
      await connection
        .query(
          `
            SELECT

              COUNT(
                CASE
                  WHEN estado <> 'cancelada'
                  THEN 1
                END
              ) AS total,

              SUM(
                CASE
                  WHEN estado = 'asignada'
                  THEN 1
                  ELSE 0
                END
              ) AS usadas,

              SUM(
                CASE
                  WHEN estado = 'disponible'
                  THEN 1
                  ELSE 0
                END
              ) AS disponibles,

              SUM(
                CASE
                  WHEN estado = 'suspendida'
                  THEN 1
                  ELSE 0
                END
              ) AS suspendidas

            FROM licencias

            WHERE
              id_suscripcion = ?
          `,
          [
            suscripcion
              .id_suscripcion
          ]
        );


    await connection
      .commit();


    const resumen =
      estadoLicencias[0] ||
      {};


    return res.json({

      success: true,

      message:
        "Licencias actualizadas correctamente.",

      id_organizacion:
        idOrganizacion,

      id_suscripcion:
        suscripcion
          .id_suscripcion,

      licencias: {

        totales:
          Number(
            resumen.total ||
            0
          ),

        usadas:
          Number(
            resumen.usadas ||
            0
          ),

        disponibles:
          Number(
            resumen.disponibles ||
            0
          ),

        suspendidas:
          Number(
            resumen.suspendidas ||
            0
          )

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
      "❌ Error ajustando licencias:",
      error
    );


    return res
      .status(
        error.status ||
        500
      )
      .json({

        success: false,

        message:
          error.message ||
          "Error al actualizar las licencias."

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

// ==================================================
// OTORGAR BENEFICIO MASTER
//
// SOLO MASTER
//
// tipo_beneficio:
// - cortesia
// - prueba
//
// Permite:
// - cambiar plan
// - definir licencias
// - definir duración
// - activar organización
// - sincronizar licencias
//
// NO CREA PAGOS
// ==================================================

export async function otorgarBeneficioMaster(
  req,
  res
) {

  let connection;

  try {

    // ================================================
    // SOLO MASTER
    // ================================================

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({

          success: false,

          message:
            "Solo el Administrador Master puede otorgar beneficios."

        });

    }


    // ================================================
    // DATOS
    // ================================================

    const idOrganizacion =
      Number(
        req.params.id
      );


    const {

      tipo_beneficio,
      id_plan,
      licencias_totales,
      dias,
      meses,
      motivo

    } =
      req.body || {};


    const tipoBeneficio =
      String(
        tipo_beneficio || ""
      )
        .trim()
        .toLowerCase();


    if (
      !idOrganizacion
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "ID de organización inválido."

        });

    }


    if (
      ![
        "cortesia",
        "prueba"
      ].includes(
        tipoBeneficio
      )
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "El tipo de beneficio debe ser cortesia o prueba."

        });

    }


    const cantidadLicencias =
      Number(
        licencias_totales
      );


    if (
      !Number.isInteger(
        cantidadLicencias
      ) ||
      cantidadLicencias < 1 ||
      cantidadLicencias > 10000
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "La cantidad de licencias no es válida."

        });

    }


    // ================================================
    // DURACIÓN
    // ================================================

    let diasBeneficio = null;
    let mesesBeneficio = null;


    if (
      tipoBeneficio ===
      "prueba"
    ) {

      diasBeneficio =
        Number(
          dias
        );


      if (
        !Number.isInteger(
          diasBeneficio
        ) ||
        diasBeneficio < 1 ||
        diasBeneficio > 365
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "Los días de prueba no son válidos."

          });

      }

    }


    if (
      tipoBeneficio ===
      "cortesia"
    ) {

      mesesBeneficio =
        Number(
          meses
        );


      if (
        !Number.isInteger(
          mesesBeneficio
        ) ||
        mesesBeneficio < 1 ||
        mesesBeneficio > 36
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "Los meses de cortesía no son válidos."

          });

      }

    }


    // ================================================
    // TRANSACCIÓN
    // ================================================

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ================================================
    // ORGANIZACIÓN
    // ================================================

    const [
      organizaciones
    ] =
      await connection
        .query(
          `
            SELECT

              id_organizacion,
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
            "Organización no encontrada."

        });

    }


    const organizacion =
      organizaciones[0];


    // ================================================
    // PLAN
    // ================================================

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
          `,
          [
            Number(
              id_plan
            )
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
            "El plan seleccionado no existe."

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
        .status(400)
        .json({

          success: false,

          message:
            "El plan seleccionado no está activo."

        });

    }


    // ================================================
    // COMPATIBILIDAD PLAN / ORGANIZACIÓN
    // ================================================

    const tipoOrganizacion =
      String(
        organizacion.tipo
      )
        .trim()
        .toLowerCase();


    const tipoPlan =
      String(
        plan.tipo
      )
        .trim()
        .toLowerCase();


    let compatible =
      tipoOrganizacion ===
      tipoPlan;


    if (
      tipoOrganizacion ===
        "independiente" &&
      tipoPlan ===
        "psicologo"
    ) {

      compatible = true;

    }


    if (
      !compatible
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({

          success: false,

          message:
            `El plan ${plan.nombre} no corresponde al tipo de organización ${tipoOrganizacion}.`

        });

    }


    // ================================================
    // SUSCRIPCIÓN ACTUAL
    // ================================================

    const [
      suscripciones
    ] =
      await connection
        .query(
          `
            SELECT *

            FROM suscripciones

            WHERE
              id_organizacion = ?

            ORDER BY
              id_suscripcion DESC

            LIMIT 1

            FOR UPDATE
          `,
          [
            idOrganizacion
          ]
        );


    const hoy =
      new Date();


    const fechaInicio =
      fechaSQL(
        hoy
      );


    let fechaFin;
    let proximaRenovacion;
    let estadoSuscripcion;


    // ================================================
    // FECHAS SEGÚN BENEFICIO
    // ================================================

    if (
      tipoBeneficio ===
      "prueba"
    ) {

      const fin =
        new Date(
          hoy
        );


      fin.setDate(
        fin.getDate() +
        diasBeneficio
      );


      fechaFin =
        fechaSQL(
          fin
        );


      proximaRenovacion =
        fechaFin;


      estadoSuscripcion =
        "prueba";

    }

    else {

      const fin =
        sumarMeses(
          hoy,
          mesesBeneficio
        );


      fechaFin =
        fechaSQL(
          fin
        );


      proximaRenovacion =
        fechaFin;


      estadoSuscripcion =
        "activa";

    }


    // ================================================
    // CREAR O ACTUALIZAR SUSCRIPCIÓN
    // ================================================

    let idSuscripcion;


    if (
      suscripciones.length
    ) {

      idSuscripcion =
        suscripciones[0]
          .id_suscripcion;


      await connection
        .query(
          `
            UPDATE suscripciones

            SET
              id_plan = ?,
              estado = ?,
              fecha_inicio = ?,
              fecha_fin = ?,
              proxima_renovacion = ?,
              licencias_totales = ?,
              origen_suscripcion = ?,
              motivo_beneficio = ?,
              otorgado_por = ?,
              fecha_otorgamiento = NOW()

            WHERE
              id_suscripcion = ?
          `,
          [
            Number(
              id_plan
            ),

            estadoSuscripcion,

            fechaInicio,

            fechaFin,

            proximaRenovacion,

            cantidadLicencias,

            tipoBeneficio,

            motivo
              ? String(
                  motivo
                ).trim()
              : null,

            Number(
              req.user.id_usuario
            ),

            idSuscripcion
          ]
        );

    }

    else {

      const [
        insert
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
                licencias_totales,
                origen_suscripcion,
                motivo_beneficio,
                otorgado_por,
                fecha_otorgamiento
              )
              VALUES
              (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, NOW()
              )
            `,
            [
              idOrganizacion,

              Number(
                id_plan
              ),

              estadoSuscripcion,

              fechaInicio,

              fechaFin,

              proximaRenovacion,

              cantidadLicencias,

              tipoBeneficio,

              motivo
                ? String(
                    motivo
                  ).trim()
                : null,

              Number(
                req.user.id_usuario
              )
            ]
          );


      idSuscripcion =
        insert.insertId;

    }


    // ================================================
    // ACTIVAR ORGANIZACIÓN
    // ================================================

    await connection
      .query(
        `
          UPDATE organizaciones

          SET
            estado = 'activa'

          WHERE
            id_organizacion = ?
        `,
        [
          idOrganizacion
        ]
      );


    // ================================================
    // SINCRONIZAR LICENCIAS
    // ================================================

    const tipoLicencia =
      obtenerTipoLicencia(
        tipoOrganizacion
      );


    if (
      !tipoLicencia
    ) {

      throw new Error(
        "No se pudo determinar el tipo de licencia."
      );

    }


    await sincronizarLicencias(
      connection,
      idSuscripcion,
      tipoLicencia,
      cantidadLicencias
    );


    // ================================================
    // CONFIRMAR
    // ================================================

    await connection
      .commit();


    return res.json({

      success: true,

      message:
        tipoBeneficio ===
        "prueba"
          ? "Prueba gratuita otorgada correctamente."
          : "Membresía de cortesía otorgada correctamente.",

      beneficio: {

        tipo:
          tipoBeneficio,

        id_organizacion:
          idOrganizacion,

        id_suscripcion:
          idSuscripcion,

        id_plan:
          Number(
            id_plan
          ),

        plan:
          plan.nombre,

        estado:
          estadoSuscripcion,

        fecha_inicio:
          fechaInicio,

        fecha_fin:
          fechaFin,

        proxima_renovacion:
          proximaRenovacion,

        licencias_totales:
          cantidadLicencias,

        motivo:
          motivo || null,

        otorgado_por:
          Number(
            req.user.id_usuario
          )

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
      "❌ Error otorgando beneficio Master:",
      error
    );


    return res
      .status(
        error.status ||
        500
      )
      .json({

        success: false,

        message:
          error.message ||
          "Error al otorgar el beneficio."

      });


  } finally {

    if (
      connection
    ) {

      connection.release();

    }

  }

}

// ==================================================
// PROCESAR SUSCRIPCIONES VENCIDAS
//
// Se puede ejecutar:
// - desde endpoint Master
// - desde cron / scheduler
//
// REGLA:
//
// fecha renovación
// +
// 3 días de gracia
// +
// sin renovación
// = vencida
//
// NO BORRA DATOS.
// ==================================================

export async function procesarSuscripcionesVencidas() {

  const [
    resultado
  ] =
    await pool.query(
      `
        UPDATE suscripciones

        SET
          estado = 'vencida',
          fecha_fin =
            COALESCE(
              fecha_fin,
              CURDATE()
            )

        WHERE
          estado IN (
            'activa',
            'prueba'
          )

          AND proxima_renovacion
              IS NOT NULL

          AND DATE_ADD(
                proxima_renovacion,
                INTERVAL ${DIAS_GRACIA} DAY
              ) < CURDATE()
      `
    );


  return {
    actualizadas:
      Number(
        resultado
          .affectedRows ||
        0
      )
  };
}


// ==================================================
// ENDPOINT MANUAL PARA REVISAR VENCIMIENTOS
//
// SOLO MASTER
// ==================================================

export async function marcarSuscripcionesVencidas(
  req,
  res
) {

  try {

    if (
      !esMaster(
        req
      )
    ) {

      return res
        .status(403)
        .json({
          success: false,

          message:
            "Acceso denegado."
        });
    }


    const resultado =
      await procesarSuscripcionesVencidas();


    return res.json({

      success: true,

      message:
        "Revisión de suscripciones terminada.",

      dias_gracia:
        DIAS_GRACIA,

      suscripciones_vencidas:
        resultado.actualizadas
    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error revisando vencimientos:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error al revisar las suscripciones."
      });
  }
}