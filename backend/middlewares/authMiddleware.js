import jwt from "jsonwebtoken";

import pool from "../config/database.js";


// ==================================================
// CONFIGURACIÓN
// ==================================================

const DIAS_GRACIA = 3;


// ==================================================
// NORMALIZAR TEXTO
// ==================================================

const normalizar = (
  valor
) => {

  return String(
    valor ?? ""
  )
    .trim()
    .toLowerCase();

};


// ==================================================
// MIDDLEWARE DE AUTENTICACIÓN
// ==================================================

export function verifyToken(
  req,
  res,
  next
) {

  const authHeader =
    req.headers[
      "authorization"
    ];


  const token =
    authHeader &&
    authHeader.split(" ")[1];


  // ==================================================
  // VERIFICAR QUE EXISTA EL TOKEN
  // ==================================================

  if (!token) {

    return res
      .status(403)
      .json({

        success: false,

        code:
          "TOKEN_REQUERIDO",

        message:
          "Token requerido"

      });

  }


  // ==================================================
  // VERIFICAR JWT
  // ==================================================

  jwt.verify(

    token,

    process.env.JWT_SECRET,

    (
      err,
      user
    ) => {

      if (err) {

        return res
          .status(401)
          .json({

            success: false,

            code:
              "TOKEN_INVALIDO",

            message:
              "Token inválido o expirado"

          });

      }


      // ==================================================
      // GUARDAR USUARIO EN LA PETICIÓN
      // ==================================================

      req.user =
        user;


      next();

    }

  );

}



// ==================================================
// VALIDAR SUSCRIPCIÓN DE LA ORGANIZACIÓN
// ==================================================
//
// IMPORTANTE:
//
// Este middleware debe ir DESPUÉS de verifyToken.
//
// Ejemplo:
//
// router.get(
//   "/",
//   verifyToken,
//   verificarSuscripcionOrganizacion,
//   controlador
// );
//
//
// REGLAS:
//
// MASTER
// --------------------------------------------------
// Nunca se bloquea.
//
// USUARIOS ANTIGUOS
// --------------------------------------------------
// Si id_organizacion es NULL,
// se mantienen funcionando para no romper
// registros anteriores.
//
// ORGANIZACIÓN
// --------------------------------------------------
// Debe estar activa.
//
// SUSCRIPCIÓN
// --------------------------------------------------
// activa  -> acceso
// prueba  -> acceso
//
// Si ya llegó la fecha de renovación:
// tiene 3 días de gracia.
//
// Después de esos 3 días:
// acceso bloqueado.
//
// vencida/cancelada:
// acceso bloqueado.
//
// ==================================================

export async function
verificarSuscripcionOrganizacion(
  req,
  res,
  next
) {

  try {

    // ==================================================
    // DATOS DEL TOKEN
    // ==================================================

    const idUsuario =
      Number(
        req.user?.id_usuario
      ) || null;


    const tipoAdmin =
      normalizar(
        req.user?.tipo_admin
      );


    // ==================================================
    // MASTER SIEMPRE PASA
    // ==================================================

    if (
      tipoAdmin ===
      "master"
    ) {

      return next();

    }


    // ==================================================
    // VALIDAR ID DE USUARIO
    // ==================================================

    if (!idUsuario) {

      return res
        .status(401)
        .json({

          success: false,

          code:
            "USUARIO_NO_IDENTIFICADO",

          message:
            "No se pudo identificar al usuario"

        });

    }


    // ==================================================
    // CONSULTAR USUARIO DIRECTAMENTE EN BD
    //
    // No confiamos únicamente en el JWT porque:
    //
    // - puede cambiar estado
    // - puede cambiar organización
    // - puede ser dado de baja
    //
    // ==================================================

    const [
      usuarios
    ] =
      await pool.query(
        `
          SELECT
            id_usuario,
            nombre,
            correo,
            rol,
            tipo_admin,
            area,
            id_admin_padre,
            id_organizacion,
            estado
          FROM usuarios
          WHERE id_usuario = ?
          LIMIT 1
        `,
        [
          idUsuario
        ]
      );


    if (
      !usuarios.length
    ) {

      return res
        .status(401)
        .json({

          success: false,

          code:
            "USUARIO_NO_ENCONTRADO",

          message:
            "Usuario no encontrado"

        });

    }


    const usuario =
      usuarios[0];


    // ==================================================
    // VALIDAR ESTADO DEL USUARIO
    // ==================================================

    if (
      normalizar(
        usuario.estado
      ) !==
      "activo"
    ) {

      return res
        .status(403)
        .json({

          success: false,

          code:
            "USUARIO_INACTIVO",

          message:
            "Tu cuenta está inactiva. Contacta al administrador de tu organización."

        });

    }


    // ==================================================
    // MASTER EN BD
    //
    // Segunda protección por si el token es antiguo.
    // ==================================================

    if (
      normalizar(
        usuario.tipo_admin
      ) ===
      "master"
    ) {

      return next();

    }


    // ==================================================
    // USUARIOS LEGACY
    //
    // Actualmente existen usuarios antiguos
    // sin organización.
    //
    // Los dejamos pasar para no romper
    // Clínica / RH existentes.
    // ==================================================

    const idOrganizacion =
      Number(
        usuario.id_organizacion
      ) || null;


    if (
      !idOrganizacion
    ) {

      req.organizacion = null;

      req.suscripcion = null;

      return next();

    }


    // ==================================================
    // CONSULTAR ORGANIZACIÓN
    // ==================================================

    const [
      organizaciones
    ] =
      await pool.query(
        `
          SELECT
            id_organizacion,
            nombre,
            nombre_comercial,
            tipo,
            estado
          FROM organizaciones
          WHERE id_organizacion = ?
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
        .status(403)
        .json({

          success: false,

          code:
            "ORGANIZACION_NO_ENCONTRADA",

          message:
            "La organización asociada a tu cuenta no existe."

        });

    }


    const organizacion =
      organizaciones[0];


    // ==================================================
    // VALIDAR ESTADO DE LA ORGANIZACIÓN
    // ==================================================

    const estadoOrganizacion =
      normalizar(
        organizacion.estado
      );


    if (
      estadoOrganizacion !==
      "activa"
    ) {

      return res
        .status(403)
        .json({

          success: false,

          code:
            "ORGANIZACION_NO_ACTIVA",

          message:
            estadoOrganizacion ===
            "suspendida"

              ? "La organización está suspendida."

              : "La organización está cancelada.",

          organizacion: {

            id_organizacion:
              organizacion
                .id_organizacion,

            nombre:
              organizacion
                .nombre,

            estado:
              organizacion
                .estado

          }

        });

    }


    // ==================================================
    // OBTENER SUSCRIPCIÓN MÁS RECIENTE
    //
    // Calculamos directamente en MySQL:
    //
    // dias_vencidos
    // fecha_limite_gracia
    //
    // para evitar problemas con zonas horarias JS.
    // ==================================================

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

            p.nombre
              AS plan_nombre,

            p.tipo
              AS plan_tipo,

            CASE

              WHEN
                s.proxima_renovacion
                IS NULL
              THEN NULL

              ELSE
                DATE_ADD(
                  s.proxima_renovacion,
                  INTERVAL ? DAY
                )

            END
              AS fecha_limite_gracia,

            CASE

              WHEN
                s.proxima_renovacion
                IS NULL
              THEN 0

              ELSE
                DATEDIFF(
                  CURDATE(),
                  s.proxima_renovacion
                )

            END
              AS dias_desde_renovacion

          FROM suscripciones s

          INNER JOIN planes p
            ON p.id_plan =
               s.id_plan

          WHERE
            s.id_organizacion = ?

          ORDER BY
            s.id_suscripcion DESC

          LIMIT 1
        `,
        [
          DIAS_GRACIA,
          idOrganizacion
        ]
      );


    // ==================================================
    // ORGANIZACIÓN SIN SUSCRIPCIÓN
    // ==================================================

    if (
      !suscripciones.length
    ) {

      return res
        .status(403)
        .json({

          success: false,

          code:
            "SIN_SUSCRIPCION",

          message:
            "La organización no tiene una suscripción activa."

        });

    }


    const suscripcion =
      suscripciones[0];


    const estadoSuscripcion =
      normalizar(
        suscripcion.estado
      );


    // ==================================================
    // CANCELADA
    // ==================================================

    if (
      estadoSuscripcion ===
      "cancelada"
    ) {

      return res
        .status(403)
        .json({

          success: false,

          code:
            "SUSCRIPCION_CANCELADA",

          message:
            "La suscripción de la organización está cancelada.",

          suscripcion: {

            id_suscripcion:
              suscripcion
                .id_suscripcion,

            estado:
              suscripcion.estado,

            plan:
              suscripcion
                .plan_nombre

          }

        });

    }


    // ==================================================
    // CALCULAR VENCIMIENTO REAL
    // ==================================================

    const diasDesdeRenovacion =
      Number(
        suscripcion
          .dias_desde_renovacion
      ) || 0;


    const tieneFechaRenovacion =
      Boolean(
        suscripcion
          .proxima_renovacion
      );


    const fueraDeGracia =

      tieneFechaRenovacion &&

      diasDesdeRenovacion >
      DIAS_GRACIA;


    // ==================================================
    // SUSCRIPCIÓN VENCIDA
    //
    // Bloqueamos si:
    //
    // 1. ya está marcada como vencida
    //
    // O
    //
    // 2. aunque la BD todavía diga activa/prueba,
    //    la fecha ya superó los 3 días.
    //
    // Esto vuelve al middleware la protección real.
    // ==================================================

    if (
      estadoSuscripcion ===
        "vencida" ||
      fueraDeGracia
    ) {

      return res
        .status(403)
        .json({

          success: false,

          code:
            "SUSCRIPCION_VENCIDA",

          message:
            "La suscripción de tu organización está vencida. Renueva el servicio para continuar.",

          dias_gracia:
            DIAS_GRACIA,

          suscripcion: {

            id_suscripcion:
              suscripcion
                .id_suscripcion,

            estado:
              suscripcion.estado,

            plan:
              suscripcion
                .plan_nombre,

            proxima_renovacion:
              suscripcion
                .proxima_renovacion,

            fecha_limite_gracia:
              suscripcion
                .fecha_limite_gracia

          }

        });

    }


    // ==================================================
    // VALIDAR ESTADO PERMITIDO
    // ==================================================

    if (
      estadoSuscripcion !==
        "activa" &&
      estadoSuscripcion !==
        "prueba"
    ) {

      return res
        .status(403)
        .json({

          success: false,

          code:
            "SUSCRIPCION_NO_ACTIVA",

          message:
            "La suscripción no permite acceder al sistema."

        });

    }


    // ==================================================
    // GUARDAR CONTEXTO
    //
    // Puede utilizarse después dentro de controladores.
    // ==================================================

    req.organizacion = {

      id_organizacion:
        organizacion
          .id_organizacion,

      nombre:
        organizacion
          .nombre,

      nombre_comercial:
        organizacion
          .nombre_comercial,

      tipo:
        organizacion.tipo,

      estado:
        organizacion.estado

    };


    req.suscripcion = {

      id_suscripcion:
        suscripcion
          .id_suscripcion,

      id_plan:
        suscripcion
          .id_plan,

      estado:
        suscripcion.estado,

      plan_nombre:
        suscripcion
          .plan_nombre,

      plan_tipo:
        suscripcion
          .plan_tipo,

      fecha_inicio:
        suscripcion
          .fecha_inicio,

      fecha_fin:
        suscripcion
          .fecha_fin,

      proxima_renovacion:
        suscripcion
          .proxima_renovacion,

      fecha_limite_gracia:
        suscripcion
          .fecha_limite_gracia,

      licencias_totales:
        suscripcion
          .licencias_totales

    };


    // ==================================================
    // TODO CORRECTO
    // ==================================================

    return next();


  } catch (
    error
  ) {

    console.error(
      "❌ Error validando suscripción:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        code:
          "ERROR_VALIDAR_SUSCRIPCION",

        message:
          "Error interno al validar la suscripción."

      });

  }

}



// ==================================================
// SOLO ADMINISTRADORES
// ==================================================

export function isAdmin(
  req,
  res,
  next
) {

  if (
    req.user?.role !== 1
  ) {

    return res
      .status(403)
      .json({

        success: false,

        message:
          "Acceso denegado: solo administradores"

      });

  }


  next();

}



// ==================================================
// SOLO ADMIN MASTER
// ==================================================
//
// Permite únicamente:
//
// rol = admin
// tipo_admin = master
//
// ==================================================

export function isMasterAdmin(
  req,
  res,
  next
) {

  // Primero debe ser administrador

  if (
    req.user?.role !== 1
  ) {

    return res
      .status(403)
      .json({

        success: false,

        message:
          "Acceso denegado: se requiere una cuenta de administrador"

      });

  }


  // Después verificamos que sea MASTER

  if (
    req.user?.tipo_admin !==
    "master"
  ) {

    return res
      .status(403)
      .json({

        success: false,

        message:
          "Acceso denegado: solo el Administrador Master puede realizar esta acción"

      });

  }


  next();

}



// ==================================================
// SOLO ADMIN NORMAL
// ==================================================
//
// Permite únicamente:
//
// rol = admin
// tipo_admin = normal
//
// ==================================================

export function isNormalAdmin(
  req,
  res,
  next
) {

  // Primero debe ser administrador

  if (
    req.user?.role !== 1
  ) {

    return res
      .status(403)
      .json({

        success: false,

        message:
          "Acceso denegado: solo administradores"

      });

  }


  // Después verificamos que sea NORMAL

  if (
    req.user?.tipo_admin !==
    "normal"
  ) {

    return res
      .status(403)
      .json({

        success: false,

        message:
          "Acceso denegado: esta acción es exclusiva para administradores normales"

      });

  }


  next();

}



// ==================================================
// ADMIN MASTER O ADMIN NORMAL
// ==================================================
//
// Permite:
//
// rol = admin
// tipo_admin = master
//
// O:
//
// rol = admin
// tipo_admin = normal
//
// ==================================================

export function
isAdminMasterOrNormal(
  req,
  res,
  next
) {

  // Debe ser administrador

  if (
    req.user?.role !== 1
  ) {

    return res
      .status(403)
      .json({

        success: false,

        message:
          "Acceso denegado: solo administradores"

      });

  }


  // Debe tener un tipo de administrador válido

  if (
    req.user?.tipo_admin !==
      "master" &&
    req.user?.tipo_admin !==
      "normal"
  ) {

    return res
      .status(403)
      .json({

        success: false,

        message:
          "Tipo de administrador inválido"

      });

  }


  next();

}



// ==================================================
// PERMISOS ESPECÍFICOS
// ==================================================

export function hasPermission(
  permisoId
) {

  return (
    req,
    res,
    next
  ) => {

    if (
      !req.user
        ?.permisos
        ?.includes(
          permisoId
        )
    ) {

      return res
        .status(403)
        .json({

          success: false,

          message:
            "Acceso denegado: permiso insuficiente"

        });

    }


    next();

  };

}