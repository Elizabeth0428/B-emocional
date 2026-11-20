// ============================================================
// backend/svc/passwordInicialService.js
// ============================================================

import crypto from "crypto";
import bcrypt from "bcryptjs";
import pool from "../config/database.js";


// ============================================================
// CONFIGURACIÓN
// ============================================================

// 60 minutos de vigencia
const MINUTOS_VIGENCIA =
  60;


// ============================================================
// HASH DEL TOKEN
// ============================================================

function hashToken(
  token
) {
  return crypto
    .createHash(
      "sha256"
    )
    .update(
      String(
        token
      )
    )
    .digest(
      "hex"
    );
}


// ============================================================
// GENERAR TOKEN ALEATORIO
// ============================================================

function generarTokenSeguro() {

  return crypto
    .randomBytes(
      32
    )
    .toString(
      "hex"
    );

}


// ============================================================
// CALCULAR EXPIRACIÓN
// ============================================================

function calcularExpiracion() {

  const fecha =
    new Date();


  fecha.setMinutes(
    fecha.getMinutes() +
    MINUTOS_VIGENCIA
  );


  return fecha;
}


// ============================================================
// CREAR TOKEN DE PASSWORD INICIAL
// ============================================================

export async function crearTokenPasswordInicial({
  idUsuario,
}) {

  const id =
    Number(
      idUsuario
    );


  if (
    !id
  ) {

    throw new Error(
      "El usuario no es válido."
    );

  }


  // ==========================================================
  // VERIFICAR USUARIO
  // ==========================================================

  const [
    usuarios
  ] =
    await pool.query(
      `
        SELECT
          id_usuario,
          nombre,
          correo,
          debe_cambiar_password

        FROM usuarios

        WHERE
          id_usuario = ?

        LIMIT 1
      `,
      [
        id
      ]
    );


  if (
    !usuarios.length
  ) {

    const error =
      new Error(
        "Usuario no encontrado."
      );

    error.status =
      404;

    throw error;

  }


  const usuario =
    usuarios[0];


  // ==========================================================
  // INVALIDAR TOKENS ANTERIORES
  // ==========================================================

  await pool.query(
    `
      UPDATE
        tokens_password_inicial

      SET
        usado = 1,
        usado_en = NOW()

      WHERE
        id_usuario = ?
        AND usado = 0
    `,
    [
      id
    ]
  );


  // ==========================================================
  // GENERAR TOKEN
  // ==========================================================

  const token =
    generarTokenSeguro();


  const tokenHash =
    hashToken(
      token
    );


  const expiraEn =
    calcularExpiracion();


  // ==========================================================
  // GUARDAR HASH
  // ==========================================================

  const [
    insert
  ] =
    await pool.query(
      `
        INSERT INTO tokens_password_inicial
        (
          id_usuario,
          token_hash,
          expira_en,
          usado
        )
        VALUES
        (
          ?,
          ?,
          ?,
          0
        )
      `,
      [
        id,
        tokenHash,
        expiraEn,
      ]
    );


  return {

    id_token:
      insert.insertId,

    id_usuario:
      id,

    nombre:
      usuario.nombre,

    correo:
      usuario.correo,

    token,

    expira_en:
      expiraEn,

  };

}


// ============================================================
// VALIDAR TOKEN
// ============================================================

export async function validarTokenPasswordInicial(
  token
) {

  if (
    !token ||
    String(
      token
    ).trim().length < 20
  ) {

    return {
      valido:
        false,

      motivo:
        "TOKEN_INVALIDO",
    };

  }


  const tokenHash =
    hashToken(
      token
    );


  const [
    rows
  ] =
    await pool.query(
      `
        SELECT
          t.id_token,
          t.id_usuario,
          t.expira_en,
          t.usado,

          u.nombre,
          u.correo,
          u.debe_cambiar_password

        FROM
          tokens_password_inicial t

        INNER JOIN
          usuarios u
            ON u.id_usuario =
               t.id_usuario

        WHERE
          t.token_hash = ?

        LIMIT 1
      `,
      [
        tokenHash
      ]
    );


  if (
    !rows.length
  ) {

    return {
      valido:
        false,

      motivo:
        "TOKEN_NO_ENCONTRADO",
    };

  }


  const registro =
    rows[0];


  // ==========================================================
  // YA FUE UTILIZADO
  // ==========================================================

  if (
    Number(
      registro.usado
    ) === 1
  ) {

    return {
      valido:
        false,

      motivo:
        "TOKEN_USADO",
    };

  }


  // ==========================================================
  // EXPIRADO
  // ==========================================================

  const ahora =
    new Date();


  const expiracion =
    new Date(
      registro.expira_en
    );


  if (
    ahora >
    expiracion
  ) {

    return {
      valido:
        false,

      motivo:
        "TOKEN_EXPIRADO",
    };

  }


  // ==========================================================
  // PASSWORD YA CONFIGURADO
  // ==========================================================

  if (
    Number(
      registro
        .debe_cambiar_password
    ) === 0
  ) {

    return {
      valido:
        false,

      motivo:
        "PASSWORD_YA_CONFIGURADO",
    };

  }


  // ==========================================================
  // TOKEN VÁLIDO
  // ==========================================================

  return {

    valido:
      true,

    id_token:
      registro.id_token,

    id_usuario:
      registro.id_usuario,

    nombre:
      registro.nombre,

    correo:
      registro.correo,

    expira_en:
      registro.expira_en,

  };

}


// ============================================================
// CREAR PASSWORD INICIAL
// ============================================================

export async function establecerPasswordInicial({
  token,
  password,
}) {

  let connection;


  try {

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ========================================================
    // VALIDAR TOKEN
    // ========================================================

    const tokenHash =
      hashToken(
        token
      );


    const [
      tokens
    ] =
      await connection.query(
        `
          SELECT
            t.id_token,
            t.id_usuario,
            t.expira_en,
            t.usado,

            u.nombre,
            u.correo,
            u.debe_cambiar_password

          FROM
            tokens_password_inicial t

          INNER JOIN
            usuarios u
              ON u.id_usuario =
                 t.id_usuario

          WHERE
            t.token_hash = ?

          LIMIT 1

          FOR UPDATE
        `,
        [
          tokenHash
        ]
      );


    if (
      !tokens.length
    ) {

      const error =
        new Error(
          "El enlace no es válido."
        );

      error.status =
        400;

      throw error;

    }


    const registro =
      tokens[0];


    // ========================================================
    // TOKEN YA USADO
    // ========================================================

    if (
      Number(
        registro.usado
      ) === 1
    ) {

      const error =
        new Error(
          "Este enlace ya fue utilizado."
        );

      error.status =
        409;

      throw error;

    }


    // ========================================================
    // TOKEN EXPIRADO
    // ========================================================

    if (
      new Date() >
      new Date(
        registro.expira_en
      )
    ) {

      const error =
        new Error(
          "El enlace para crear la contraseña ha expirado."
        );

      error.status =
        410;

      throw error;

    }


    // ========================================================
    // PASSWORD YA CONFIGURADO
    // ========================================================

    if (
      Number(
        registro
          .debe_cambiar_password
      ) === 0
    ) {

      const error =
        new Error(
          "La contraseña de esta cuenta ya fue configurada."
        );

      error.status =
        409;

      throw error;

    }


    // ========================================================
    // VALIDAR PASSWORD
    // ========================================================

    const passwordLimpio =
      String(
        password ||
        ""
      );


    if (
      passwordLimpio.length <
      8
    ) {

      const error =
        new Error(
          "La contraseña debe tener al menos 8 caracteres."
        );

      error.status =
        400;

      throw error;

    }


    if (
      !/[A-Z]/.test(
        passwordLimpio
      )
    ) {

      const error =
        new Error(
          "La contraseña debe incluir al menos una letra mayúscula."
        );

      error.status =
        400;

      throw error;

    }


    if (
      !/[a-z]/.test(
        passwordLimpio
      )
    ) {

      const error =
        new Error(
          "La contraseña debe incluir al menos una letra minúscula."
        );

      error.status =
        400;

      throw error;

    }


    if (
      !/[0-9]/.test(
        passwordLimpio
      )
    ) {

      const error =
        new Error(
          "La contraseña debe incluir al menos un número."
        );

      error.status =
        400;

      throw error;

    }


    // ========================================================
    // HASH PASSWORD
    // ========================================================

    const passwordHash =
      await bcrypt.hash(
        passwordLimpio,
        10
      );


    // ========================================================
    // ACTUALIZAR USUARIO
    // ========================================================

    await connection.query(
      `
        UPDATE usuarios

        SET
          password = ?,
          debe_cambiar_password = 0

        WHERE
          id_usuario = ?
      `,
      [
        passwordHash,

        registro
          .id_usuario,
      ]
    );


    // ========================================================
    // MARCAR TOKEN COMO USADO
    // ========================================================

    await connection.query(
      `
        UPDATE
          tokens_password_inicial

        SET
          usado = 1,
          usado_en = NOW()

        WHERE
          id_token = ?
      `,
      [
        registro
          .id_token
      ]
    );


    // ========================================================
    // INVALIDAR OTROS TOKENS
    // ========================================================

    await connection.query(
      `
        UPDATE
          tokens_password_inicial

        SET
          usado = 1,
          usado_en =
            COALESCE(
              usado_en,
              NOW()
            )

        WHERE
          id_usuario = ?
          AND usado = 0
      `,
      [
        registro
          .id_usuario
      ]
    );


    await connection
      .commit();


    return {

      ok:
        true,

      id_usuario:
        registro.id_usuario,

      nombre:
        registro.nombre,

      correo:
        registro.correo,

    };


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


    throw error;


  } finally {

    if (
      connection
    ) {

      connection.release();

    }

  }

}