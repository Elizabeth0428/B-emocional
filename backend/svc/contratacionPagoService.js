
import crypto from "crypto";
import bcrypt from "bcryptjs";
import pool from "../config/database.js";

import {
  crearTokenPasswordInicial,
} from "./passwordInicialService.js";

import {
  enviarCorreoCrearPassword,
  correoConfigurado,
} from "./correoService.js";

import {
  registrarCorreoPendiente,
  registrarIntentoCorreo,
  marcarCorreoAceptado,
  marcarErrorCorreo,
} from "./correosActivacionService.js";

// ============================================================
// HELPERS
// ============================================================

// ============================================================
// FORMATEAR FECHA MYSQL
// ============================================================

function fechaSQL(fecha) {
  const d = new Date(fecha);

  const yyyy = d.getFullYear();

  const mm = String(
    d.getMonth() + 1
  ).padStart(2, "0");

  const dd = String(
    d.getDate()
  ).padStart(2, "0");

  return `${yyyy}-${mm}-${dd}`;
}

// ============================================================
// SUMAR MESES SIN DESBORDAR FIN DE MES
// ============================================================

function sumarMeses(fecha, cantidad) {
  const d = new Date(fecha);
  const diaOriginal = d.getDate();

  d.setDate(1);
  d.setMonth(d.getMonth() + Number(cantidad || 0));

  const ultimoDia = new Date(
    d.getFullYear(),
    d.getMonth() + 1,
    0
  ).getDate();

  d.setDate(
    Math.min(diaOriginal, ultimoDia)
  );

  return d;
}

// ============================================================
// GENERAR PASSWORD INTERNO
//
// Nunca se envía al usuario.
// ============================================================

function generarPasswordTemporal() {
  return `Ms${crypto.randomBytes(16).toString("hex")}!`;
}

// ============================================================
// TIPO DE LICENCIA POR PLAN
// ============================================================

function obtenerTipoLicencia(tipoOrganizacion) {
  const tipo = String(
    tipoOrganizacion || ""
  )
    .trim()
    .toLowerCase();

  switch (tipo) {
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

// ============================================================
// ENVÍO Y REGISTRO DEL CORREO DE ACTIVACIÓN
//
// 1. Registra el correo pendiente.
// 2. Comprueba la configuración SMTP.
// 3. Registra el intento.
// 4. Genera el token.
// 5. Envía el correo.
// 6. Guarda el resultado en MySQL.
//
// IMPORTANTE:
// SMTP aceptado NO equivale a correo entregado.
// ============================================================

async function enviarAccesoInicial({
  idUsuario,
  idOrganizacion,
  correo,
}) {
  const resultado = {
    token_generado: false,
    correo_enviado: false,
    correo_aceptado_smtp: false,
    error_correo: null,
  };

  let idCorreo = null;

  // ==========================================================
  // REGISTRAR CORREO PENDIENTE
  // ==========================================================

  try {
    idCorreo = await registrarCorreoPendiente({
      idUsuario,
      idOrganizacion,
      correo,
    });

    console.log(
      "📋 Correo de activación registrado:",
      idCorreo
    );
  } catch (error) {
    resultado.error_correo =
      "ERROR_REGISTRO_CORREO";

    console.error(
      "❌ No se pudo registrar el correo:",
      error.message
    );

    return resultado;
  }

  // ==========================================================
  // COMPROBAR CONFIGURACIÓN SMTP
  // ==========================================================

  if (!correoConfigurado()) {
    resultado.error_correo =
      "SMTP_NO_CONFIGURADO";

    console.warn(
      "⚠️ SMTP no configurado. Correo pendiente:",
      idCorreo
    );

    return resultado;
  }

  // ==========================================================
  // REGISTRAR INTENTO
  // ==========================================================

  try {
    await registrarIntentoCorreo(idCorreo);
  } catch (error) {
    resultado.error_correo =
      "ERROR_REGISTRO_INTENTO";

    console.error(
      "❌ No se pudo registrar el intento:",
      error.message
    );

    return resultado;
  }

  // ==========================================================
  // GENERAR TOKEN Y ENVIAR CORREO
  // ==========================================================

  let envio = null;

  try {
    const acceso =
      await crearTokenPasswordInicial({
        idUsuario,
      });

    resultado.token_generado =
      Boolean(acceso?.token);

    if (!acceso?.token || !acceso?.correo) {
      throw new Error(
        "No se pudo generar el enlace de activación."
      );
    }

    envio = await enviarCorreoCrearPassword({
      correo: acceso.correo,
      nombre: acceso.nombre,
      token: acceso.token,
    });

    // ========================================================
    // VERIFICAR ACEPTACIÓN SMTP
    // ========================================================

    const aceptados = Array.isArray(
      envio?.accepted
    )
      ? envio.accepted
      : [];

    const correoAceptado = aceptados.some(
      (destinatario) =>
        String(destinatario)
          .trim()
          .toLowerCase() ===
        String(acceso.correo)
          .trim()
          .toLowerCase()
    );

    if (!correoAceptado) {
      throw new Error(
        "DESTINATARIO_NO_ACEPTADO"
      );
    }

    resultado.correo_enviado = true;
    resultado.correo_aceptado_smtp = true;

    console.log(
      "✅ SMTP aceptó el correo de activación:",
      acceso.correo
    );

    console.log(
      "📨 Message ID:",
      envio.messageId || "No disponible"
    );
  } catch (error) {
    resultado.error_correo =
      error.code ||
      error.message ||
      "ERROR_ENVIO_CORREO";

    console.error(
      "❌ Error enviando correo de activación:",
      resultado.error_correo
    );

    // ========================================================
    // GUARDAR ERROR EN MYSQL
    // ========================================================

    try {
      await marcarErrorCorreo({
        idCorreo,
        error: resultado.error_correo,
      });

      console.log(
        "⚠️ Error de correo registrado en MySQL:",
        idCorreo
      );
    } catch (registroError) {
      console.error(
        "❌ No se pudo guardar el error de correo:",
        registroError.message
      );
    }

    return resultado;
  }

  // ==========================================================
  // MARCAR ACEPTACIÓN SMTP EN MYSQL
  // ==========================================================

  try {
    await marcarCorreoAceptado({
      idCorreo,
      messageId: envio.messageId,
    });

    console.log(
      "✅ Estado aceptado_smtp guardado:",
      idCorreo
    );
  } catch (error) {
    resultado.error_correo =
      "ERROR_GUARDANDO_CONFIRMACION";

    // No reenviar automáticamente: SMTP ya lo aceptó.
    console.error(
      "⚠️ SMTP aceptó el correo, pero no se pudo actualizar MySQL:",
      error.message
    );
  }

  return resultado;
}

// ============================================================
// GUARDAR CONTRATACIÓN PENDIENTE
// ============================================================

export async function guardarContratacionPendiente({
  externalReference,
  mercadopagoPreapprovalId,
  tipoPlan,
  periodo,
  nombreOrganizacion,
  nombreResponsable,
  correo,
  telefono,
  requiereFactura,
  rfc,
  monto,
  moneda = "MXN",
}) {
  const [result] = await pool.query(
    `
    INSERT INTO contrataciones_mirrorsoul
    (
      external_reference,
      mercadopago_preapproval_id,
      tipo_plan,
      periodo,
      nombre_organizacion,
      nombre_responsable,
      correo,
      telefono,
      requiere_factura,
      rfc,
      monto,
      moneda,
      estado_pago,
      estado_activacion
    )
    VALUES
    (
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      'pending',
      'pendiente'
    )

    ON DUPLICATE KEY UPDATE

      mercadopago_preapproval_id =
        VALUES(mercadopago_preapproval_id),

      actualizado_en =
        CURRENT_TIMESTAMP
    `,
    [
      externalReference,
      mercadopagoPreapprovalId,
      tipoPlan,
      periodo,
      nombreOrganizacion || null,
      nombreResponsable,
      String(correo).trim().toLowerCase(),
      telefono || null,
      requiereFactura ? 1 : 0,
      requiereFactura && rfc
        ? String(rfc).trim().toUpperCase()
        : null,
      Number(monto),
      moneda,
    ]
  );

  return {
    id_contratacion:
      result.insertId || null,

    external_reference:
      externalReference,
  };
}

// ============================================================
// ACTUALIZAR ESTADO DE MERCADO PAGO
// ============================================================

export async function actualizarEstadoMercadoPago({
  externalReference,
  preapprovalId,
  status,
}) {
  await pool.query(
    `
    UPDATE contrataciones_mirrorsoul

    SET
      estado_pago = ?,

      mercadopago_preapproval_id =
        COALESCE(
          ?,
          mercadopago_preapproval_id
        )

    WHERE external_reference = ?
    `,
    [
      String(status || "")
        .trim()
        .toLowerCase(),

      preapprovalId || null,

      externalReference,
    ]
  );
}

// ============================================================
// OBTENER CONTRATACIÓN POR REFERENCIA
// ============================================================

export async function obtenerContratacionPorReferencia(
  externalReference
) {
  const [rows] = await pool.query(
    `
    SELECT *
    FROM contrataciones_mirrorsoul
    WHERE external_reference = ?
    LIMIT 1
    `,
    [externalReference]
  );

  return rows[0] || null;
}

// ============================================================
// ACTIVAR CONTRATACIÓN AUTORIZADA
//
// - Idempotente.
// - Transacción MySQL.
// - No duplica organizaciones.
// - No duplica administradores.
// - No duplica licencias.
// - El administrador no consume licencia.
// - El correo se envía después del COMMIT.
// ============================================================

export async function activarContratacionAutorizada({
  externalReference,
  preapprovalId,
}) {
  let connection = null;
  let transaccionActiva = false;

  try {
    // ========================================================
    // INICIAR CONEXIÓN Y TRANSACCIÓN
    // ========================================================

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    transaccionActiva = true;

    // ========================================================
    // BUSCAR CONTRATACIÓN
    // ========================================================

    const [contrataciones] =
      await connection.query(
        `
        SELECT *
        FROM contrataciones_mirrorsoul

        WHERE external_reference = ?

        LIMIT 1
        FOR UPDATE
        `,
        [externalReference]
      );

    if (!contrataciones.length) {
      const error = new Error(
        "No existe la contratación asociada al pago."
      );

      error.status = 404;

      throw error;
    }

    const contratacion =
      contrataciones[0];

    // ========================================================
    // CONTRATACIÓN YA ACTIVADA
    //
    // NO crea otra organización.
    // NO crea licencias adicionales.
    // NO genera otro token.
    // NO envía otro correo.
    // ========================================================

    if (
      String(
        contratacion.estado_activacion || ""
      )
        .trim()
        .toLowerCase() === "activada" &&
      contratacion.id_organizacion
    ) {
      const idUsuarioAdmin =
        Number(
          contratacion.id_usuario_admin
        ) || null;

      let adminExistente = null;

      if (idUsuarioAdmin) {
        const [usuarios] =
          await connection.query(
            `
            SELECT
              id_usuario,
              correo,
              debe_cambiar_password

            FROM usuarios

            WHERE id_usuario = ?

            LIMIT 1
            `,
            [idUsuarioAdmin]
          );

        adminExistente =
          usuarios[0] || null;
      }

      await connection.commit();

      transaccionActiva = false;

      console.log(
        "ℹ️ Contratación ya activada:",
        externalReference
      );

      return {
        ya_activada: true,

        id_organizacion:
          contratacion.id_organizacion,

        id_suscripcion:
          contratacion.id_suscripcion,

        id_usuario_admin:
          idUsuarioAdmin,

        correo_admin:
          adminExistente?.correo || null,

        requiere_configurar_password:
          Number(
            adminExistente?.debe_cambiar_password
          ) === 1,

        token_generado: false,

        correo_enviado: false,
      };
    }

    // ========================================================
    // OBTENER TIPO DE PLAN
    // ========================================================

    const tipoPlan = String(
      contratacion.tipo_plan || ""
    )
      .trim()
      .toLowerCase();

    // ========================================================
    // PLAN INDEPENDIENTE
    // ========================================================

    if (tipoPlan === "independiente") {
      const error = new Error(
        "El plan independiente utiliza el flujo independiente existente."
      );

      error.status = 409;

      throw error;
    }

    // ========================================================
    // VALIDAR TIPO DE PLAN
    // ========================================================

    if (
      ![
        "clinica",
        "rh",
        "educativo",
      ].includes(tipoPlan)
    ) {
      const error = new Error(
        "Tipo de plan no compatible con activación automática."
      );

      error.status = 400;

      throw error;
    }

    // ========================================================
    // BUSCAR PLAN ACTIVO
    // ========================================================

    const [planes] =
      await connection.query(
        `
        SELECT
          id_plan,
          nombre,
          tipo,
          licencias_incluidas,
          activo

        FROM planes

        WHERE tipo = ?
          AND activo = 1

        ORDER BY id_plan ASC

        LIMIT 1
        FOR UPDATE
        `,
        [tipoPlan]
      );

    if (!planes.length) {
      const error = new Error(
        `No existe un plan activo tipo ${tipoPlan}.`
      );

      error.status = 409;

      throw error;
    }

    const plan = planes[0];

    // ========================================================
    // OBTENER CANTIDAD DE LICENCIAS
    // ========================================================

    const cantidadLicencias = Math.max(
      1,
      Number(
        plan.licencias_incluidas || 1
      )
    );

    const tipoLicencia =
      obtenerTipoLicencia(tipoPlan);

    if (!tipoLicencia) {
      const error = new Error(
        `No se pudo determinar el tipo de licencia para ${tipoPlan}.`
      );

      error.status = 400;

      throw error;
    }

    // ========================================================
    // CORREO DEL ADMINISTRADOR
    // ========================================================

    const correo = String(
      contratacion.correo || ""
    )
      .trim()
      .toLowerCase();

    if (!correo) {
      throw new Error(
        "La contratación no tiene correo de administrador."
      );
    }

    // ========================================================
    // VALIDAR CORREO DUPLICADO
    // ========================================================

    const [usuariosExistentes] =
      await connection.query(
        `
        SELECT
          id_usuario,
          id_organizacion

        FROM usuarios

        WHERE LOWER(
          TRIM(correo)
        ) = ?

        LIMIT 1
        FOR UPDATE
        `,
        [correo]
      );

    if (usuariosExistentes.length) {
      const error = new Error(
        "El correo del responsable ya pertenece a un usuario de MirrorSoul."
      );

      error.status = 409;

      throw error;
    }

    // ========================================================
    // OBTENER ADMINISTRADOR MASTER
    // ========================================================

    const [masters] =
      await connection.query(
        `
        SELECT id_usuario

        FROM usuarios

        WHERE rol = 'admin'
          AND tipo_admin = 'master'

        ORDER BY id_usuario ASC

        LIMIT 1
        `
      );

    if (!masters.length) {
      const error = new Error(
        "No existe un Administrador Master para asignar la organización."
      );

      error.status = 409;

      throw error;
    }

    const idAdminMaster =
      masters[0].id_usuario;

    // ========================================================
    // NOMBRE DE LA ORGANIZACIÓN
    // ========================================================

    const nombreOrganizacion = String(
      contratacion.nombre_organizacion ||
        `Organización de ${contratacion.nombre_responsable}`
    ).trim();

    // ========================================================
    // CREAR ORGANIZACIÓN
    // ========================================================

    const [organizacionInsert] =
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
          ?, ?, ?, ?, ?, ?,
          NULL, ?, 'activa'
        )
        `,
        [
          nombreOrganizacion,

          nombreOrganizacion,

          String(
            contratacion.nombre_responsable
          ).trim(),

          correo,

          contratacion.telefono || null,

          contratacion.rfc || null,

          tipoPlan,
        ]
      );

    const idOrganizacion =
      organizacionInsert.insertId;

    // ========================================================
    // CALCULAR FECHAS
    // ========================================================

    const hoy = new Date();

    const meses =
      String(
        contratacion.periodo || "mensual"
      )
        .trim()
        .toLowerCase() === "anual"
        ? 12
        : 1;

    const fechaInicio =
      fechaSQL(hoy);

    const proximaRenovacion =
      fechaSQL(
        sumarMeses(hoy, meses)
      );

    // ========================================================
    // CREAR SUSCRIPCIÓN INTERNA
    // ========================================================

    const [suscripcionInsert] =
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
          ?, ?, 'activa',
          ?, NULL, ?, ?
        )
        `,
        [
          idOrganizacion,

          plan.id_plan,

          fechaInicio,

          proximaRenovacion,

          cantidadLicencias,
        ]
      );

    const idSuscripcion =
      suscripcionInsert.insertId;

    // ========================================================
    // CREAR LICENCIAS
    // ========================================================

    for (
      let i = 0;
      i < cantidadLicencias;
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
          tipoLicencia,
        ]
      );
    }

    // ========================================================
    // GENERAR CONTRASEÑA TEMPORAL INTERNA
    //
    // No se comparte ni se envía por correo.
    // ========================================================

    const passwordTemporal =
      generarPasswordTemporal();

    const passwordHash =
      await bcrypt.hash(
        passwordTemporal,
        10
      );

    // ========================================================
    // CREAR ADMINISTRADOR NORMAL
    //
    // No consume licencia.
    // ========================================================

    const [adminInsert] =
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
          debe_cambiar_password,
          rol,
          tipo_admin,
          area,
          id_admin_padre,
          id_organizacion
        )

        VALUES
        (
          ?,
          'Administrador',
          ?,
          NULL,
          ?,
          ?,
          1,
          'admin',
          'normal',
          ?,
          ?,
          ?
        )
        `,
        [
          String(
            contratacion.nombre_responsable
          ).trim(),

          contratacion.telefono || null,

          correo,

          passwordHash,

          tipoPlan,

          idAdminMaster,

          idOrganizacion,
        ]
      );

    const idUsuarioAdmin =
      adminInsert.insertId;

    // ========================================================
    // MARCAR CONTRATACIÓN COMO ACTIVADA
    // ========================================================

    await connection.query(
      `
      UPDATE contrataciones_mirrorsoul

      SET
        estado_pago = 'authorized',

        estado_activacion = 'activada',

        mercadopago_preapproval_id =
          COALESCE(
            ?,
            mercadopago_preapproval_id
          ),

        id_organizacion = ?,

        id_suscripcion = ?,

        id_usuario_admin = ?,

        error_activacion = NULL

      WHERE id_contratacion = ?
      `,
      [
        preapprovalId || null,

        idOrganizacion,

        idSuscripcion,

        idUsuarioAdmin,

        contratacion.id_contratacion,
      ]
    );

    // ========================================================
    // CONFIRMAR TRANSACCIÓN PRINCIPAL
    // ========================================================

    await connection.commit();

    transaccionActiva = false;

    console.log(
      "✅ Organización activada:",
      idOrganizacion
    );

    console.log(
      "✅ Administrador creado:",
      idUsuarioAdmin
    );

    console.log(
      "✅ Licencias creadas:",
      cantidadLicencias
    );

    // ========================================================
    // ENVIAR ACCESO INICIAL Y REGISTRARLO EN MYSQL
    //
    // Si falla, NO desactiva la organización.
    // ========================================================

    const acceso =
      await enviarAccesoInicial({
        idUsuario: idUsuarioAdmin,

        idOrganizacion,

        correo,
      });

    // ========================================================
    // RESPUESTA FINAL
    // ========================================================

    return {
      ya_activada: false,

      id_organizacion:
        idOrganizacion,

      id_suscripcion:
        idSuscripcion,

      id_usuario_admin:
        idUsuarioAdmin,

      correo_admin:
        correo,

      requiere_configurar_password:
        true,

      token_generado:
        acceso.token_generado,

      correo_enviado:
        acceso.correo_enviado,

      correo_aceptado_smtp:
        acceso.correo_aceptado_smtp,

      error_correo:
        acceso.error_correo,

      plan: {
        id_plan:
          plan.id_plan,

        nombre:
          plan.nombre,

        tipo:
          tipoPlan,

        licencias:
          cantidadLicencias,

        tipo_licencia:
          tipoLicencia,
      },
    };
  } catch (error) {
    // ========================================================
    // ROLLBACK SOLO DE TRANSACCIONES SIN CONFIRMAR
    // ========================================================

    if (
      connection &&
      transaccionActiva
    ) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error(
          "❌ Error ejecutando rollback:",
          rollbackError.message
        );
      }

      // ======================================================
      // REGISTRAR ERROR DE ACTIVACIÓN
      // ======================================================

      try {
        await pool.query(
          `
          UPDATE contrataciones_mirrorsoul

          SET
            estado_activacion = 'error',
            error_activacion = ?

          WHERE external_reference = ?
            AND estado_activacion <> 'activada'
          `,
          [
            error.message ||
              "Error desconocido",

            externalReference,
          ]
        );
      } catch (updateError) {
        console.error(
          "⚠️ No se pudo registrar el error de activación:",
          updateError.message
        );
      }
    }

    console.error(
      "❌ Error en activación MirrorSoul:",
      error.message
    );

    throw error;
  } finally {
    // ========================================================
    // LIBERAR CONEXIÓN
    // ========================================================

    if (connection) {
      connection.release();
    }
  }
}
