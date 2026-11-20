
import nodemailer from "nodemailer";

// ============================================================
// CONFIGURACIÓN SMTP
// ============================================================

function obtenerConfiguracionSMTP() {
  return {
    host: String(process.env.SMTP_HOST || "").trim(),
    port: Number(process.env.SMTP_PORT || 587),
    secure:
      String(process.env.SMTP_SECURE || "false")
        .trim()
        .toLowerCase() === "true",
    user: String(process.env.SMTP_USER || "").trim(),
    pass: String(process.env.SMTP_PASS || "").trim(),
    fromName: String(
      process.env.SMTP_FROM_NAME || "MirrorSoul"
    ).trim(),
    fromEmail: String(
      process.env.SMTP_FROM_EMAIL ||
      process.env.SMTP_USER ||
      ""
    ).trim(),
  };
}

// ============================================================
// VALIDAR CONFIGURACIÓN
// ============================================================

export function correoConfigurado() {
  const config = obtenerConfiguracionSMTP();

  return Boolean(
    config.host &&
    Number.isInteger(config.port) &&
    config.port > 0 &&
    config.user &&
    config.pass &&
    config.fromEmail
  );
}

// ============================================================
// TRANSPORTER
// ============================================================

function crearTransporter() {
  if (!correoConfigurado()) {
    const error = new Error(
      "El servicio SMTP de MirrorSoul no está configurado."
    );

    error.code = "SMTP_NO_CONFIGURADO";
    throw error;
  }

  const config = obtenerConfiguracionSMTP();

  return nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    requireTLS: config.port === 587,
    auth: {
      user: config.user,
      pass: config.pass,
    },
  });
}

// ============================================================
// ENVIAR CORREO GENÉRICO
// ============================================================

export async function enviarCorreo({
  para,
  asunto,
  html,
  texto,
}) {
  const destinatario = String(para || "")
    .trim()
    .toLowerCase();

  if (
    !destinatario ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(destinatario)
  ) {
    throw new Error(
      "El destinatario del correo no es válido."
    );
  }

  if (!String(asunto || "").trim()) {
    throw new Error(
      "El asunto del correo es obligatorio."
    );
  }

  const config = obtenerConfiguracionSMTP();
  const transporter = crearTransporter();

  const resultado = await transporter.sendMail({
    from: {
      name: config.fromName,
      address: config.fromEmail,
    },
    to: destinatario,
    subject: asunto,
    text: texto || undefined,
    html: html || undefined,
  });

  return {
    ok: true,
    messageId: resultado.messageId,
    accepted: resultado.accepted,
    rejected: resultado.rejected,
  };
}

// ============================================================
// SEGURIDAD PARA CONTENIDO HTML
// ============================================================

function escaparHTML(valor) {
  return String(valor ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ============================================================
// URL PARA CREAR CONTRASEÑA
//
// IMPORTANTE:
// FRONTEND_URL: retorno público de Mercado Pago.
// FRONTEND_ACCESO_URL: formulario de contraseña.
// ============================================================

function obtenerUrlAcceso() {
  const direccion = String(
    process.env.FRONTEND_ACCESO_URL ||
    process.env.FRONTEND_URL ||
    "https://www.reflejoyalma.com"
  ).trim();

  if (!direccion) {
    throw new Error(
      "No se configuró la URL de acceso de MirrorSoul."
    );
  }

  const url = new URL(direccion);

  if (
    url.protocol !== "https:" &&
    !(
      url.protocol === "http:" &&
      ["localhost", "127.0.0.1"].includes(url.hostname)
    )
  ) {
    throw new Error(
      "La URL de acceso debe utilizar HTTPS, excepto en localhost."
    );
  }

  return url.origin;
}

// ============================================================
// CORREO PARA CREAR CONTRASEÑA
// ============================================================

export async function enviarCorreoCrearPassword({
  correo,
  nombre,
  token,
}) {
  const destinatario = String(correo || "")
    .trim()
    .toLowerCase();

  const nombreUsuario = String(
    nombre || "Administrador"
  ).trim();

  const tokenSeguro = String(token || "").trim();

  if (!destinatario) {
    throw new Error(
      "No se recibió el correo del administrador."
    );
  }

  if (!tokenSeguro) {
    throw new Error(
      "No se recibió el token de acceso."
    );
  }

  // ==========================================================
  // GENERAR ENLACE SEGURO
  // ==========================================================

  const frontendUrl = obtenerUrlAcceso();

  const url = new URL(
    "/crear-password",
    frontendUrl
  );

  url.searchParams.set("token", tokenSeguro);

  const enlace = url.toString();

  const asunto = "Activa tu acceso a MirrorSoul";

  const nombreHTML = escaparHTML(nombreUsuario);
  const enlaceHTML = escaparHTML(enlace);

  // ==========================================================
  // VERSIÓN TEXTO
  // ==========================================================

  const texto = `
Hola ${nombreUsuario}:

Tu suscripción a MirrorSoul fue activada correctamente.

Para comenzar, crea tu contraseña desde este enlace:

${enlace}

El enlace es personal, de un solo uso y tiene una
vigencia limitada de 60 minutos.

Si no realizaste esta contratación, ignora este mensaje.

MirrorSoul
Plataforma de evaluación y acompañamiento emocional
  `.trim();

  // ==========================================================
  // VERSIÓN HTML
  // ==========================================================

  const html = `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >
  <title>Activa tu acceso a MirrorSoul</title>
</head>

<body style="
  margin:0;
  padding:0;
  background:#f1f5f9;
  font-family:Arial,Helvetica,sans-serif;
  color:#0f172a;
">

  <table
    role="presentation"
    width="100%"
    cellpadding="0"
    cellspacing="0"
    style="background:#f1f5f9;padding:35px 15px;"
  >
    <tr>
      <td align="center">

        <table
          role="presentation"
          width="600"
          cellpadding="0"
          cellspacing="0"
          style="
            width:100%;
            max-width:600px;
            background:#ffffff;
            border-radius:20px;
            overflow:hidden;
            border:1px solid #e2e8f0;
          "
        >

          <!-- CABECERA -->
          <tr>
            <td
              align="center"
              bgcolor="#0f172a"
              style="
                background:#0f172a;
                padding:40px 25px;
              "
            >

              <div style="
                color:#7dd3fc;
                font-size:14px;
                letter-spacing:4px;
                font-weight:bold;
              ">
                MIRRORSOUL
              </div>

              <h1 style="
                color:#ffffff;
                margin:15px 0 0;
                font-size:30px;
                line-height:1.3;
              ">
                Tu cuenta está lista
              </h1>

            </td>
          </tr>

          <!-- CONTENIDO -->
          <tr>
            <td style="padding:40px 35px;">

              <p style="
                margin:0 0 24px;
                font-size:18px;
                line-height:1.5;
              ">
                Hola <strong>${nombreHTML}</strong>,
              </p>

              <p style="
                color:#475569;
                font-size:16px;
                line-height:1.8;
              ">
                Tu suscripción a
                <strong>MirrorSoul</strong>
                ya fue activada correctamente.
              </p>

              <p style="
                color:#475569;
                font-size:16px;
                line-height:1.8;
              ">
                Para comenzar a utilizar la plataforma,
                crea una contraseña segura para tu cuenta.
              </p>

              <!-- BOTÓN DE ACCESO -->
              <table
                role="presentation"
                width="100%"
                cellpadding="0"
                cellspacing="0"
                style="margin:35px 0;"
              >
                <tr>
                  <td align="center">

                    <a
                      href="${enlaceHTML}"
                      style="
                        display:inline-block;
                        background:#2563eb;
                        color:#ffffff;
                        text-decoration:none;
                        padding:17px 32px;
                        border-radius:12px;
                        font-size:16px;
                        font-weight:bold;
                      "
                    >
                      Crear mi contraseña
                    </a>

                  </td>
                </tr>
              </table>

              <div style="
                background:#f8fafc;
                border:1px solid #e2e8f0;
                border-radius:12px;
                padding:20px;
              ">

                <p style="
                  color:#475569;
                  font-size:14px;
                  line-height:1.7;
                  margin:0;
                ">
                  🔒 Este enlace es personal,
                  de un solo uso y tiene una
                  vigencia de 60 minutos.
                </p>

              </div>

              <p style="
                color:#94a3b8;
                font-size:12px;
                line-height:1.7;
                margin-top:30px;
              ">
                Si tú no realizaste esta contratación,
                puedes ignorar este correo.
              </p>

            </td>
          </tr>

          <!-- PIE -->
          <tr>
            <td
              align="center"
              bgcolor="#f8fafc"
              style="
                background:#f8fafc;
                padding:28px;
                color:#64748b;
                font-size:12px;
                line-height:1.8;
              "
            >
              <strong>MirrorSoul</strong>
              <div>
                Plataforma de evaluación y
                acompañamiento emocional
              </div>
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>

</body>
</html>
  `.trim();

  // ==========================================================
  // ENVIAR
  // ==========================================================

  return enviarCorreo({
    para: destinatario,
    asunto,
    texto,
    html,
  });
}
