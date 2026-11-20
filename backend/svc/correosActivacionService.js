
import pool from "../config/database.js";

// ============================================================
// SERVICIO DE SEGUIMIENTO DE CORREOS
// MIRRORSOUL
// ============================================================

// ============================================================
// REGISTRAR CORREO PENDIENTE
// ============================================================

export async function registrarCorreoPendiente({
  idUsuario,
  idOrganizacion,
  correo,
}) {
  const [resultado] = await pool.query(
    `
    INSERT INTO correos_activacion (
      id_usuario,
      id_organizacion,
      correo_destinatario,
      estado,
      intentos
    )
    VALUES (?, ?, ?, 'pendiente', 0)
    `,
    [
      idUsuario,
      idOrganizacion,
      String(correo).trim().toLowerCase(),
    ]
  );

  return resultado.insertId;
}

// ============================================================
// MARCAR INICIO DE INTENTO
// ============================================================

export async function registrarIntentoCorreo(idCorreo) {
  await pool.query(
    `
    UPDATE correos_activacion
    SET
      intentos = intentos + 1,
      fecha_ultimo_intento = NOW(),
      ultimo_error = NULL
    WHERE id_correo = ?
      AND estado IN ('pendiente', 'error')
    `,
    [idCorreo]
  );
}

// ============================================================
// CORREO ACEPTADO POR SMTP
//
// No significa entrega confirmada al destinatario.
// ============================================================

export async function marcarCorreoAceptado({
  idCorreo,
  messageId,
}) {
  await pool.query(
    `
    UPDATE correos_activacion
    SET
      estado = 'aceptado_smtp',
      message_id = ?,
      ultimo_error = NULL,
      fecha_aceptacion = NOW()
    WHERE id_correo = ?
    `,
    [messageId || null, idCorreo]
  );
}

// ============================================================
// REGISTRAR ERROR DEL CORREO
// ============================================================

export async function marcarErrorCorreo({
  idCorreo,
  error,
}) {
  await pool.query(
    `
    UPDATE correos_activacion
    SET
      estado = 'error',
      ultimo_error = ?
    WHERE id_correo = ?
    `,
    [
      String(error || "Error desconocido").slice(0, 2000),
      idCorreo,
    ]
  );
}

// ============================================================
// CONSULTAR HISTORIAL DE UN ADMINISTRADOR
// ============================================================

export async function obtenerCorreosUsuario(idUsuario) {
  const [rows] = await pool.query(
    `
    SELECT
      id_correo,
      id_usuario,
      id_organizacion,
      correo_destinatario,
      estado,
      intentos,
      ultimo_error,
      message_id,
      fecha_creacion,
      fecha_ultimo_intento,
      fecha_aceptacion
    FROM correos_activacion
    WHERE id_usuario = ?
    ORDER BY id_correo DESC
    `,
    [idUsuario]
  );

  return rows;
}
