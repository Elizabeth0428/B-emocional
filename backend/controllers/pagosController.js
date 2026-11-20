
// ============================================================
// backend/controllers/pagosController.js
// ============================================================

import {
  crearSuscripcion,
  obtenerSuscripcion,
  obtenerPago,
  validarWebhook,
} from "../svc/mercadoPagoService.js";

import {
  guardarContratacionPendiente,
  actualizarEstadoMercadoPago,
  obtenerContratacionPorReferencia,
  activarContratacionAutorizada,
} from "../svc/contratacionPagoService.js";

// ============================================================
// PRECIOS DE PLANES
// ============================================================

const PLANES = {
  independiente: {
    nombre: "Independiente",
    licencias: 1,
    mensual: Number(process.env.PRECIO_INDEPENDIENTE_MENSUAL || 0),
    anual: Number(process.env.PRECIO_INDEPENDIENTE_ANUAL || 0),
  },

  clinica: {
    nombre: "Clínica",
    licencias: 5,
    mensual: Number(process.env.PRECIO_CLINICA_MENSUAL || 0),
    anual: Number(process.env.PRECIO_CLINICA_ANUAL || 0),
  },

  rh: {
    nombre: "Recursos Humanos",
    licencias: 5,
    mensual: Number(process.env.PRECIO_RH_MENSUAL || 0),
    anual: Number(process.env.PRECIO_RH_ANUAL || 0),
  },

  educativo: {
    nombre: "Educativo",
    licencias: 5,
    mensual: Number(process.env.PRECIO_EDUCATIVO_MENSUAL || 0),
    anual: Number(process.env.PRECIO_EDUCATIVO_ANUAL || 0),
  },
};

// ============================================================
// HELPERS
// ============================================================

function normalizarTexto(valor) {
  return valor == null ? "" : String(valor).trim();
}

function normalizarCorreo(valor) {
  return normalizarTexto(valor).toLowerCase();
}

// ============================================================
// RESOLVER PLAN
// ============================================================

function resolverPlan(tipoPlan, periodo) {
  const tipo = normalizarTexto(tipoPlan).toLowerCase();
  const plan = PLANES[tipo];

  if (!plan) {
    const error = new Error("Plan no válido");
    error.status = 400;
    throw error;
  }

  const periodoFinal =
    normalizarTexto(periodo).toLowerCase() === "anual"
      ? "anual"
      : "mensual";

  const precio = Number(plan[periodoFinal]);

  if (!Number.isFinite(precio) || precio <= 0) {
    const error = new Error(
      `El precio del plan ${plan.nombre} (${periodoFinal}) todavía no está configurado`
    );
    error.status = 409;
    throw error;
  }

  return {
    tipo,
    ...plan,
    periodo: periodoFinal,
    precio,
  };
}

// ============================================================
// GET /api/pagos/precio
// ============================================================

export async function obtenerPrecioPlan(req, res) {
  try {
    const plan = resolverPlan(
      req.query.plan,
      req.query.periodo || "mensual"
    );

    return res.json({
      ok: true,
      plan: {
        tipo: plan.tipo,
        nombre: plan.nombre,
        periodo: plan.periodo,
        precio: plan.precio,
        moneda: "MXN",
        licencias: plan.licencias,
      },
    });
  } catch (error) {
    console.error("❌ Error consultando precio:", error);

    return res.status(error.status || 500).json({
      ok: false,
      message: error.message || "No se pudo consultar el precio",
    });
  }
}

// ============================================================
// POST /api/pagos/crear-suscripcion
//
// 1. Recibe datos del cliente.
// 2. Calcula el precio.
// 3. Separa correo del cliente y comprador de prueba.
// 4. Crea la suscripción en Mercado Pago.
// 5. Guarda la contratación pendiente.
// 6. Devuelve el enlace de pago.
// ============================================================

export async function crearSuscripcionMirrorSoul(req, res) {
  try {
    const {
      tipo_plan,
      periodo_facturacion,
      correo,
      nombre_responsable,
      nombre_organizacion,
      telefono,
      requiere_factura,
      rfc,
    } = req.body || {};

    // ========================================================
    // NORMALIZAR DATOS
    // ========================================================

    const tipoPlan =
      normalizarTexto(tipo_plan).toLowerCase();

    const correoNormalizado =
      normalizarCorreo(correo);

    const responsableNormalizado =
      normalizarTexto(nombre_responsable);

    const organizacionNormalizada =
      normalizarTexto(nombre_organizacion);

    const telefonoNormalizado =
      normalizarTexto(telefono);

    const rfcNormalizado =
      normalizarTexto(rfc).toUpperCase();

    const requiereFactura =
      requiere_factura === true ||
      requiere_factura === 1 ||
      requiere_factura === "true";

    // ========================================================
    // VALIDACIONES
    // ========================================================

    if (!tipoPlan) {
      return res.status(400).json({
        ok: false,
        message: "Falta tipo_plan",
      });
    }

    if (!correoNormalizado) {
      return res.status(400).json({
        ok: false,
        message: "Falta el correo del responsable",
      });
    }

    if (!responsableNormalizado) {
      return res.status(400).json({
        ok: false,
        message: "Falta el nombre del responsable",
      });
    }

    if (
      tipoPlan !== "independiente" &&
      !organizacionNormalizada
    ) {
      return res.status(400).json({
        ok: false,
        message: "Falta el nombre de la organización",
      });
    }

    if (requiereFactura && !rfcNormalizado) {
      return res.status(400).json({
        ok: false,
        message:
          "El RFC es obligatorio cuando se solicita factura",
      });
    }

    // ========================================================
    // PLAN Y PRECIO
    // ========================================================

    const plan = resolverPlan(
      tipoPlan,
      periodo_facturacion
    );

    // ========================================================
    // URL DEL FRONTEND
    // ========================================================

    const frontendUrl = String(
      process.env.FRONTEND_URL ||
      "https://www.reflejoyalma.com"
    )
      .trim()
      .replace(/\/+$/, "");

    // ========================================================
    // REFERENCIA ÚNICA
    // ========================================================

    const reference = [
      "MS",
      plan.tipo,
      plan.periodo,
      Date.now(),
    ].join("-");

    // ========================================================
    // FRECUENCIA DE SUSCRIPCIÓN
    // ========================================================

    const frequency =
      plan.periodo === "anual" ? 12 : 1;

    // ========================================================
    // COMPRADOR DE PRUEBA MERCADO PAGO
    // ========================================================

    const modoPrueba =
      process.env.MERCADOPAGO_MODO_PRUEBA === "true";

    const correoCompradorMP = modoPrueba
      ? normalizarCorreo(
          process.env.MERCADOPAGO_PAYER_TEST_EMAIL
        )
      : correoNormalizado;

    if (!correoCompradorMP) {
      return res.status(500).json({
        ok: false,
        message:
          "Falta configurar MERCADOPAGO_PAYER_TEST_EMAIL en el backend",
      });
    }

    // ========================================================
    // CREAR SUSCRIPCIÓN EN MERCADO PAGO
    // ========================================================

    const suscripcion = await crearSuscripcion({
      reason: `MirrorSoul - Plan ${plan.nombre}`,

      payerEmail: correoCompradorMP,

      amount: plan.precio,

      frequency,

      frequencyType: "months",

      externalReference: reference,

      backUrl: `${frontendUrl}/pago-exitoso`,
    });

    if (!suscripcion?.id) {
      throw new Error(
        "Mercado Pago no devolvió el ID de la suscripción."
      );
    }

    // ========================================================
    // GUARDAR CONTRATACIÓN PENDIENTE
    //
    // IMPORTANTE:
    // Se guarda el correo REAL del administrador.
    // No se guarda el comprador de prueba como cliente.
    // ========================================================

    await guardarContratacionPendiente({
      externalReference: reference,

      mercadopagoPreapprovalId:
        suscripcion.id,

      tipoPlan: plan.tipo,

      periodo: plan.periodo,

      nombreOrganizacion:
        organizacionNormalizada || null,

      nombreResponsable:
        responsableNormalizado,

      correo: correoNormalizado,

      telefono:
        telefonoNormalizado || null,

      requiereFactura,

      rfc: requiereFactura
        ? rfcNormalizado || null
        : null,

      monto: plan.precio,

      moneda: "MXN",
    });

    // ========================================================
    // RESPUESTA AL FRONTEND
    // ========================================================

    return res.json({
      ok: true,

      message: "Suscripción creada",

      plan: {
        tipo: plan.tipo,
        nombre: plan.nombre,
        periodo: plan.periodo,
        precio: plan.precio,
        moneda: "MXN",
        licencias: plan.licencias,
      },

      contratacion: {
        nombre_responsable:
          responsableNormalizado,

        nombre_organizacion:
          organizacionNormalizada || null,

        correo: correoNormalizado,

        telefono:
          telefonoNormalizado || null,

        requiere_factura:
          requiereFactura,

        rfc: requiereFactura
          ? rfcNormalizado || null
          : null,
      },

      mercado_pago: {
        id: suscripcion.id,

        status: suscripcion.status,

        init_point: suscripcion.init_point,

        external_reference:
          suscripcion.external_reference ||
          reference,
      },
    });
  } catch (error) {
    console.error(
      "❌ Error creando suscripción Mercado Pago:",
      error
    );

    return res.status(error.status || 500).json({
      ok: false,

      message:
        error.message ||
        "No se pudo crear la suscripción",

      details:
        error.details || undefined,
    });
  }
}

// ============================================================
// GET /api/pagos/suscripcion/:id
// ============================================================

export async function obtenerEstadoSuscripcion(req, res) {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "Falta el ID de la suscripción.",
      });
    }

    // ========================================================
    // CONSULTAR MERCADO PAGO
    // ========================================================

    const data = await obtenerSuscripcion(id);

    const status =
      normalizarTexto(data?.status).toLowerCase();

    const externalReference =
      normalizarTexto(data?.external_reference);

    // ========================================================
    // ACTUALIZAR ESTADO INTERNO
    // ========================================================

    if (externalReference) {
      try {
        await actualizarEstadoMercadoPago({
          externalReference,

          preapprovalId:
            data.id || id,

          status:
            status || "unknown",
        });
      } catch (updateError) {
        console.error(
          "⚠️ No se pudo actualizar estado interno:",
          updateError
        );
      }
    }

    // ========================================================
    // ACTIVAR MIRRORSOUL SI ESTÁ AUTORIZADA
    // ========================================================

    if (
      status === "authorized" &&
      externalReference
    ) {
      try {
        const activacion =
          await activarContratacionAutorizada({
            externalReference,

            preapprovalId:
              data.id || id,
          });

        data.activacion_mirrorsoul = {
          ok: true,

          ya_activada:
            Boolean(activacion.ya_activada),

          id_organizacion:
            activacion.id_organizacion,

          id_suscripcion:
            activacion.id_suscripcion,

          id_usuario_admin:
            activacion.id_usuario_admin,

          correo_admin:
            activacion.correo_admin || null,

          requiere_configurar_password:
            Boolean(
              activacion.requiere_configurar_password
            ),

          token_generado:
            Boolean(activacion.token_generado),

          plan:
            activacion.plan || null,
        };

        // No mostrar contraseñas ni tokens.
        if (
          process.env.NODE_ENV !== "production"
        ) {
          console.log(
            "🔐 Estado acceso inicial:",
            {
              requiere_configurar_password:
                Boolean(
                  activacion.requiere_configurar_password
                ),

              token_generado:
                Boolean(activacion.token_generado),
            }
          );
        }
      } catch (activationError) {
        console.error(
          "❌ Mercado Pago autorizado pero falló activación MirrorSoul:",
          activationError
        );

        data.activacion_mirrorsoul = {
          ok: false,

          message:
            activationError.message ||
            "No se pudo activar MirrorSoul.",
        };
      }
    }

    return res.json({
      ok: true,
      suscripcion: data,
    });
  } catch (error) {
    console.error(
      "❌ Error consultando suscripción:",
      error
    );

    return res.status(error.status || 500).json({
      ok: false,

      message:
        error.message ||
        "No se pudo consultar la suscripción",

      details:
        error.details || undefined,
    });
  }
}

// ============================================================
// GET /api/pagos/contratacion/:externalReference
// ============================================================

export async function obtenerEstadoContratacion(req, res) {
  try {
    const externalReference =
      normalizarTexto(
        req.params.externalReference
      );

    if (!externalReference) {
      return res.status(400).json({
        ok: false,
        message: "Referencia inválida.",
      });
    }

    const contratacion =
      await obtenerContratacionPorReferencia(
        externalReference
      );

    if (!contratacion) {
      return res.status(404).json({
        ok: false,
        message: "Contratación no encontrada",
      });
    }

    return res.json({
      ok: true,

      contratacion: {
        id_contratacion:
          contratacion.id_contratacion,

        external_reference:
          contratacion.external_reference,

        mercadopago_preapproval_id:
          contratacion.mercadopago_preapproval_id,

        tipo_plan:
          contratacion.tipo_plan,

        periodo:
          contratacion.periodo,

        nombre_organizacion:
          contratacion.nombre_organizacion,

        nombre_responsable:
          contratacion.nombre_responsable,

        correo:
          contratacion.correo,

        telefono:
          contratacion.telefono,

        requiere_factura:
          Boolean(
            contratacion.requiere_factura
          ),

        rfc:
          contratacion.rfc,

        monto:
          Number(contratacion.monto || 0),

        moneda:
          contratacion.moneda,

        estado_pago:
          contratacion.estado_pago,

        estado_activacion:
          contratacion.estado_activacion,

        id_organizacion:
          contratacion.id_organizacion,

        id_suscripcion:
          contratacion.id_suscripcion,

        id_usuario_admin:
          contratacion.id_usuario_admin,

        error_activacion:
          contratacion.error_activacion,

        creado_en:
          contratacion.creado_en,

        actualizado_en:
          contratacion.actualizado_en,
      },
    });
  } catch (error) {
    console.error(
      "❌ Error consultando contratación:",
      error
    );

    return res.status(error.status || 500).json({
      ok: false,

      message:
        error.message ||
        "No se pudo consultar la contratación",
    });
  }
}

// ============================================================
// POST /api/pagos/webhook
// ============================================================

export async function webhookMercadoPago(req, res) {
  try {
    const xSignature =
      req.headers["x-signature"];

    const xRequestId =
      req.headers["x-request-id"];

    const dataId =
      req.query["data.id"] ||
      req.query.data_id ||
      req.body?.data?.id ||
      null;

    // ========================================================
    // VALIDAR FIRMA DEL WEBHOOK
    // ========================================================

    const firmaValida = validarWebhook({
      xSignature,

      xRequestId,

      dataId:
        dataId ? String(dataId) : null,
    });

    if (!firmaValida) {
      console.warn(
        "⚠️ Webhook Mercado Pago con firma inválida"
      );

      return res.status(401).json({
        ok: false,
      });
    }

    // ========================================================
    // RESPONDER A MERCADO PAGO
    // ========================================================

    res.status(200).json({
      ok: true,
    });

    const type =
      req.body?.type ||
      req.query?.type ||
      "";

    console.log(
      "🔔 Webhook Mercado Pago:",
      {
        type,
        dataId,
        action: req.body?.action,
      }
    );

    // ========================================================
    // EVENTO DE SUSCRIPCIÓN
    // ========================================================

    if (
      type === "subscription_preapproval" &&
      dataId
    ) {
      const suscripcion =
        await obtenerSuscripcion(dataId);

      const status =
        normalizarTexto(
          suscripcion?.status
        ).toLowerCase();

      const externalReference =
        normalizarTexto(
          suscripcion?.external_reference
        );

      console.log(
        "📌 Estado suscripción:",
        {
          id: suscripcion.id,
          status,

          external_reference:
            externalReference,

          payer_email:
            suscripcion.payer_email,
        }
      );

      // ======================================================
      // ACTUALIZAR CONTRATACIÓN
      // ======================================================

      if (externalReference) {
        await actualizarEstadoMercadoPago({
          externalReference,

          preapprovalId:
            suscripcion.id,

          status:
            status || "unknown",
        });
      }

      // ======================================================
      // ACTIVAR CONTRATACIÓN
      // ======================================================

      if (
        status === "authorized" &&
        externalReference
      ) {
        const activacion =
          await activarContratacionAutorizada({
            externalReference,

            preapprovalId:
              suscripcion.id,
          });

        console.log(
          "✅ MirrorSoul activado:",
          {
            id_organizacion:
              activacion.id_organizacion,

            id_suscripcion:
              activacion.id_suscripcion,

            id_usuario_admin:
              activacion.id_usuario_admin,

            ya_activada:
              activacion.ya_activada,

            requiere_configurar_password:
              Boolean(
                activacion.requiere_configurar_password
              ),

            token_generado:
              Boolean(activacion.token_generado),
          }
        );

        // No exponer contraseñas temporales.
        if (
          process.env.NODE_ENV !== "production"
        ) {
          console.log(
            "🔐 Estado acceso inicial:",
            {
              requiere_configurar_password:
                Boolean(
                  activacion.requiere_configurar_password
                ),

              token_generado:
                Boolean(
                  activacion.token_generado
                ),
            }
          );
        }
      }

      return;
    }

    // ========================================================
    // EVENTO DE PAGO
    // ========================================================

    if (
      type === "payment" &&
      dataId
    ) {
      const pago =
        await obtenerPago(dataId);

      console.log(
        "💳 Estado pago:",
        {
          id: pago.id,

          status:
            pago.status,

          status_detail:
            pago.status_detail,

          external_reference:
            pago.external_reference,
        }
      );
    }
  } catch (error) {
    console.error(
      "❌ Error procesando webhook Mercado Pago:",
      error
    );

    if (!res.headersSent) {
      return res.status(500).json({
        ok: false,
        message: "Error procesando webhook",
      });
    }
  }
}
