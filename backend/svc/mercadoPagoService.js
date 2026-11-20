// backend/services/mercadoPagoService.js

import crypto from "crypto";

const MP_API =
  "https://api.mercadopago.com";

function getAccessToken() {
  const token =
    process.env.MERCADOPAGO_ACCESS_TOKEN;

  if (!token) {
    throw new Error(
      "Falta MERCADOPAGO_ACCESS_TOKEN en el archivo .env"
    );
  }

  return token;
}

async function mpRequest(
  path,
  options = {}
) {
  const token =
    getAccessToken();

  const response =
    await fetch(
      `${MP_API}${path}`,
      {
        ...options,

        headers: {
          Authorization:
            `Bearer ${token}`,

          "Content-Type":
            "application/json",

          ...(options.headers || {}),
        },
      }
    );

  const data =
    await response
      .json()
      .catch(
        () => ({})
      );

  if (!response.ok) {
    const error =
      new Error(
        data?.message ||
        data?.error ||
        `Mercado Pago respondió ${response.status}`
      );

    error.status =
      response.status;

    error.details =
      data;

    throw error;
  }

  return data;
}


// ============================================================
// CREAR SUSCRIPCIÓN
// ============================================================

export async function crearSuscripcion({
  reason,
  payerEmail,
  amount,
  frequency,
  frequencyType,
  externalReference,
  backUrl,
}) {
  const body = {
    reason,

    payer_email:
      payerEmail,

    external_reference:
      externalReference,

    back_url:
      backUrl,

    auto_recurring: {
      frequency,

      frequency_type:
        frequencyType,

      transaction_amount:
        Number(amount),

      currency_id:
        "MXN",
    },
  };

  return mpRequest(
    "/preapproval",
    {
      method:
        "POST",

      body:
        JSON.stringify(
          body
        ),
    }
  );
}


// ============================================================
// CONSULTAR SUSCRIPCIÓN
// ============================================================

export async function obtenerSuscripcion(
  id
) {
  return mpRequest(
    `/preapproval/${encodeURIComponent(id)}`,
    {
      method:
        "GET",
    }
  );
}


// ============================================================
// CONSULTAR PAGO
// ============================================================

export async function obtenerPago(
  id
) {
  return mpRequest(
    `/v1/payments/${encodeURIComponent(id)}`,
    {
      method:
        "GET",
    }
  );
}


// ============================================================
// VALIDAR WEBHOOK
// ============================================================

export function validarWebhook({
  xSignature,
  xRequestId,
  dataId,
}) {
  const secret =
    process.env.MERCADOPAGO_WEBHOOK_SECRET;

  if (!secret) {
    throw new Error(
      "Falta MERCADOPAGO_WEBHOOK_SECRET en el archivo .env"
    );
  }

  if (!xSignature) {
    return false;
  }

  const parts =
    String(xSignature)
      .split(",");

  let ts =
    null;

  let v1 =
    null;

  for (
    const part of parts
  ) {
    const [
      key,
      value,
    ] =
      part
        .split("=")
        .map(
          item =>
            item.trim()
        );

    if (key === "ts") {
      ts =
        value;
    }

    if (key === "v1") {
      v1 =
        value;
    }
  }

  if (
    !ts ||
    !v1
  ) {
    return false;
  }

  const manifestParts =
    [];

  if (dataId) {
    manifestParts.push(
      `id:${dataId};`
    );
  }

  if (xRequestId) {
    manifestParts.push(
      `request-id:${xRequestId};`
    );
  }

  manifestParts.push(
    `ts:${ts};`
  );

  const manifest =
    manifestParts.join("");

  const calculada =
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(
        manifest
      )
      .digest(
        "hex"
      );

  try {
    return crypto
      .timingSafeEqual(
        Buffer.from(
          calculada,
          "hex"
        ),
        Buffer.from(
          v1,
          "hex"
        )
      );
  } catch {
    return false;
  }
}
