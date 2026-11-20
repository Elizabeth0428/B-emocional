// ==================================================
// backend/controllers/psicologoEstadoController.js
// ==================================================

import pool
from "../config/database.js";


// ==================================================
// AUXILIARES
// ==================================================

const normalizar =
  valor =>
    valor
      ? String(valor)
          .trim()
          .toLowerCase()
      : "";


const enteroPositivo =
  valor => {

    const numero =
      Number(valor);

    return (
      Number.isInteger(numero) &&
      numero > 0
    )
      ? numero
      : null;
  };


// ==================================================
// OBTENER ADMIN REAL
// ==================================================

const obtenerAdministrador =
  async (
    req,
    connection
  ) => {

    const idUsuario =
      enteroPositivo(
        req.user?.id_usuario
      );


    if (!idUsuario) {

      return null;

    }


    const [rows] =
      await connection.query(
        `
          SELECT

            id_usuario,
            rol,
            tipo_admin,
            area,
            id_admin_padre,
            id_organizacion,
            estado

          FROM usuarios

          WHERE
            id_usuario = ?

          LIMIT 1
        `,
        [
          idUsuario
        ]
      );


    return rows[0] || null;

  };


// ==================================================
// VALIDAR ADMINISTRADOR
// ==================================================

const validarAdministrador =
  administrador => {

    if (!administrador) {

      return {
        ok: false,
        status: 401,
        message:
          "No se pudo identificar al administrador"
      };

    }


    if (
      normalizar(
        administrador.estado
      ) !==
      "activo"
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "La cuenta del administrador está inactiva"
      };

    }


    if (
      normalizar(
        administrador.rol
      ) !==
      "admin"
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "Solo los administradores pueden realizar esta acción"
      };

    }


    const tipoAdmin =
      normalizar(
        administrador.tipo_admin
      );


    if (
      tipoAdmin !== "master" &&
      tipoAdmin !== "normal"
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "Tipo de administrador inválido"
      };

    }


    if (
      tipoAdmin === "normal" &&
      normalizar(
        administrador.area
      ) !==
      "clinica"
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "No tienes acceso al módulo de psicólogos"
      };

    }


    return {
      ok: true,
      tipoAdmin
    };

  };


// ==================================================
// BUSCAR PSICÓLOGO
// ==================================================

const buscarPsicologo =
  async (
    idPsicologo,
    connection
  ) => {

    const [rows] =
      await connection.query(
        `
          SELECT

            p.id_psicologo,
            p.id_usuario,

            u.nombre,
            u.correo,
            u.rol,
            u.estado AS estado_usuario,
            u.id_admin_padre,
            u.id_organizacion,

            p.activo_canalizacion

          FROM psicologos p

          INNER JOIN usuarios u
            ON u.id_usuario =
               p.id_usuario

          WHERE
            p.id_psicologo = ?

          LIMIT 1

          FOR UPDATE
        `,
        [
          idPsicologo
        ]
      );


    return rows[0] || null;

  };


// ==================================================
// VALIDAR PROPIEDAD DEL PSICÓLOGO
// ==================================================

const validarPropiedad =
  (
    administrador,
    psicologo
  ) => {

    const tipoAdmin =
      normalizar(
        administrador.tipo_admin
      );


    // MASTER VE TODO
    if (
      tipoAdmin ===
      "master"
    ) {

      return {
        ok: true
      };

    }


    // ADMIN NORMAL:
    // psicólogo debe pertenecer
    // a su misma organización.
    const idOrganizacionAdmin =
      enteroPositivo(
        administrador.id_organizacion
      );


    const idOrganizacionPsicologo =
      enteroPositivo(
        psicologo.id_organizacion
      );


    if (
      !idOrganizacionAdmin
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "El administrador no está asociado a una organización"
      };

    }


    if (
      idOrganizacionAdmin !==
      idOrganizacionPsicologo
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "No puedes modificar psicólogos de otra organización"
      };

    }


    return {
      ok: true
    };

  };


// ==================================================
// DESACTIVAR PSICÓLOGO
//
// PATCH
// /api/psicologos/:id/desactivar
//
// NO BORRA:
// - usuario
// - psicólogo
// - pacientes
// - sesiones
// - reportes
// - pruebas
// - archivos
//
// SOLO:
// - usuario = inactivo
// - canalización = 0
// - libera licencia
// ==================================================

export async function desactivarPsicologo(
  req,
  res
) {

  let connection;


  try {

    const idPsicologo =
      enteroPositivo(
        req.params?.id
      );


    if (!idPsicologo) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "El ID del psicólogo no es válido"

        });

    }


    // ==================================================
    // TRANSACCIÓN
    // ==================================================

    connection =
      await pool.getConnection();


    await connection.beginTransaction();


    // ==================================================
    // ADMINISTRADOR
    // ==================================================

    const administrador =
      await obtenerAdministrador(
        req,
        connection
      );


    const validacionAdmin =
      validarAdministrador(
        administrador
      );


    if (!validacionAdmin.ok) {

      await connection.rollback();


      return res
        .status(
          validacionAdmin.status
        )
        .json({

          success: false,

          message:
            validacionAdmin.message

        });

    }


    // ==================================================
    // PSICÓLOGO
    // ==================================================

    const psicologo =
      await buscarPsicologo(
        idPsicologo,
        connection
      );


    if (!psicologo) {

      await connection.rollback();


      return res
        .status(404)
        .json({

          success: false,

          message:
            "Psicólogo no encontrado"

        });

    }


    if (
      normalizar(
        psicologo.rol
      ) !==
      "psicologo"
    ) {

      await connection.rollback();


      return res
        .status(400)
        .json({

          success: false,

          message:
            "El usuario seleccionado no es un psicólogo"

        });

    }


    // ==================================================
    // VALIDAR ORGANIZACIÓN
    // ==================================================

    const propiedad =
      validarPropiedad(
        administrador,
        psicologo
      );


    if (!propiedad.ok) {

      await connection.rollback();


      return res
        .status(
          propiedad.status
        )
        .json({

          success: false,

          message:
            propiedad.message

        });

    }


    // ==================================================
    // SI YA ESTÁ INACTIVO
    //
    // Aun así verificamos/liberamos cualquier
    // licencia que haya quedado asignada.
    // ==================================================

    await connection.query(
      `
        UPDATE usuarios

        SET
          estado = 'inactivo'

        WHERE
          id_usuario = ?
      `,
      [
        psicologo.id_usuario
      ]
    );


    // ==================================================
    // SACAR DE CANALIZACIÓN
    // ==================================================

    await connection.query(
      `
        UPDATE psicologos

        SET
          activo_canalizacion = 0

        WHERE
          id_psicologo = ?
      `,
      [
        idPsicologo
      ]
    );


    // ==================================================
    // LIBERAR LICENCIA
    // ==================================================

    const [licenciaLiberada] =
      await connection.query(
        `
          UPDATE licencias

          SET

            id_usuario = NULL,

            estado =
              'disponible',

            fecha_liberacion =
              NOW()

          WHERE
            id_usuario = ?

            AND estado =
              'asignada'
        `,
        [
          psicologo.id_usuario
        ]
      );


    // ==================================================
    // CONFIRMAR
    // ==================================================

    await connection.commit();


    return res.json({

      success: true,

      message:
        "Psicólogo dado de baja correctamente",

      psicologo: {

        id_psicologo:
          psicologo.id_psicologo,

        id_usuario:
          psicologo.id_usuario,

        nombre:
          psicologo.nombre,

        correo:
          psicologo.correo,

        id_organizacion:
          psicologo.id_organizacion,

        estado:
          "inactivo",

        licencia_liberada:
          licenciaLiberada
            .affectedRows > 0

      }

    });


  } catch (error) {

    if (connection) {

      try {

        await connection.rollback();

      } catch {}

    }


    console.error(
      "❌ Error dando de baja al psicólogo:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al dar de baja al psicólogo",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined

      });


  } finally {

    if (connection) {

      connection.release();

    }

  }

}


// ==================================================
// REACTIVAR PSICÓLOGO
//
// PATCH
// /api/psicologos/:id/reactivar
//
// REQUIERE:
// - organización activa
// - suscripción activa/prueba
// - estar dentro de renovación + gracia
// - licencia disponible
// ==================================================

export async function reactivarPsicologo(
  req,
  res
) {

  let connection;


  try {

    const idPsicologo =
      enteroPositivo(
        req.params?.id
      );


    if (!idPsicologo) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "El ID del psicólogo no es válido"

        });

    }


    // ==================================================
    // TRANSACCIÓN
    // ==================================================

    connection =
      await pool.getConnection();


    await connection.beginTransaction();


    // ==================================================
    // ADMINISTRADOR
    // ==================================================

    const administrador =
      await obtenerAdministrador(
        req,
        connection
      );


    const validacionAdmin =
      validarAdministrador(
        administrador
      );


    if (!validacionAdmin.ok) {

      await connection.rollback();


      return res
        .status(
          validacionAdmin.status
        )
        .json({

          success: false,

          message:
            validacionAdmin.message

        });

    }


    // ==================================================
    // PSICÓLOGO
    // ==================================================

    const psicologo =
      await buscarPsicologo(
        idPsicologo,
        connection
      );


    if (!psicologo) {

      await connection.rollback();


      return res
        .status(404)
        .json({

          success: false,

          message:
            "Psicólogo no encontrado"

        });

    }


    // ==================================================
    // VALIDAR ORGANIZACIÓN DEL ADMIN
    // ==================================================

    const propiedad =
      validarPropiedad(
        administrador,
        psicologo
      );


    if (!propiedad.ok) {

      await connection.rollback();


      return res
        .status(
          propiedad.status
        )
        .json({

          success: false,

          message:
            propiedad.message

        });

    }


    const idOrganizacion =
      enteroPositivo(
        psicologo.id_organizacion
      );


    if (!idOrganizacion) {

      await connection.rollback();


      return res
        .status(400)
        .json({

          success: false,

          message:
            "El psicólogo no está asociado a una organización"

        });

    }


    // ==================================================
    // ORGANIZACIÓN ACTIVA
    // ==================================================

    const [organizaciones] =
      await connection.query(
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


    if (!organizaciones.length) {

      await connection.rollback();


      return res
        .status(404)
        .json({

          success: false,

          message:
            "Organización no encontrada"

        });

    }


    const organizacion =
      organizaciones[0];


    if (
      normalizar(
        organizacion.estado
      ) !==
      "activa"
    ) {

      await connection.rollback();


      return res
        .status(403)
        .json({

          success: false,

          message:
            "La organización no está activa"

        });

    }


    // ==================================================
    // SI YA TIENE LICENCIA
    // ==================================================

    const [licenciaActual] =
      await connection.query(
        `
          SELECT

            id_licencia,
            id_suscripcion,
            estado

          FROM licencias

          WHERE
            id_usuario = ?

            AND estado =
              'asignada'

          LIMIT 1

          FOR UPDATE
        `,
        [
          psicologo.id_usuario
        ]
      );


    if (
      licenciaActual.length
    ) {

      await connection.query(
        `
          UPDATE usuarios

          SET
            estado = 'activo'

          WHERE
            id_usuario = ?
        `,
        [
          psicologo.id_usuario
        ]
      );


      await connection.commit();


      return res.json({

        success: true,

        message:
          "Psicólogo reactivado correctamente",

        psicologo: {

          id_psicologo:
            psicologo.id_psicologo,

          id_usuario:
            psicologo.id_usuario,

          estado:
            "activo",

          id_licencia:
            licenciaActual[0]
              .id_licencia

        }

      });

    }


    // ==================================================
    // SUSCRIPCIÓN ACTIVA
    // ==================================================

    const [suscripciones] =
      await connection.query(
        `
          SELECT

            id_suscripcion,
            id_organizacion,
            estado,
            fecha_inicio,
            fecha_fin,
            proxima_renovacion,
            licencias_totales

          FROM suscripciones

          WHERE
            id_organizacion = ?

            AND estado IN
            (
              'activa',
              'prueba'
            )

            AND
            (
              proxima_renovacion
                IS NULL

              OR

              DATE_ADD(
                proxima_renovacion,
                INTERVAL 3 DAY
              ) >= CURDATE()
            )

          ORDER BY
            id_suscripcion DESC

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

      await connection.rollback();


      return res
        .status(402)
        .json({

          success: false,

          code:
            "SUSCRIPCION_NO_ACTIVA",

          message:
            "La suscripción está vencida o no está activa"

        });

    }


    const suscripcion =
      suscripciones[0];


    // ==================================================
    // BUSCAR LICENCIA DISPONIBLE
    // ==================================================

    const [licencias] =
      await connection.query(
        `
          SELECT

            id_licencia,
            id_suscripcion,
            tipo,
            estado

          FROM licencias

          WHERE
            id_suscripcion = ?

            AND tipo =
              'psicologo'

            AND estado =
              'disponible'

            AND id_usuario
              IS NULL

          ORDER BY
            id_licencia ASC

          LIMIT 1

          FOR UPDATE
        `,
        [
          suscripcion
            .id_suscripcion
        ]
      );


    if (
      !licencias.length
    ) {

      await connection.rollback();


      return res
        .status(409)
        .json({

          success: false,

          code:
            "SIN_LICENCIAS",

          message:
            "No hay licencias disponibles para reactivar al psicólogo"

        });

    }


    const idLicencia =
      licencias[0]
        .id_licencia;


    // ==================================================
    // ASIGNAR LICENCIA
    // ==================================================

    const [resultadoLicencia] =
      await connection.query(
        `
          UPDATE licencias

          SET

            id_usuario = ?,

            estado =
              'asignada',

            fecha_asignacion =
              NOW(),

            fecha_liberacion =
              NULL

          WHERE
            id_licencia = ?

            AND estado =
              'disponible'

            AND id_usuario
              IS NULL
        `,
        [
          psicologo.id_usuario,
          idLicencia
        ]
      );


    if (
      resultadoLicencia
        .affectedRows !== 1
    ) {

      throw new Error(
        "No fue posible asignar la licencia"
      );

    }


    // ==================================================
    // REACTIVAR USUARIO
    // ==================================================

    await connection.query(
      `
        UPDATE usuarios

        SET
          estado = 'activo'

        WHERE
          id_usuario = ?
      `,
      [
        psicologo.id_usuario
      ]
    );


    // ==================================================
    // CONFIRMAR
    // ==================================================

    await connection.commit();


    return res.json({

      success: true,

      message:
        "Psicólogo reactivado correctamente y licencia asignada",

      psicologo: {

        id_psicologo:
          psicologo.id_psicologo,

        id_usuario:
          psicologo.id_usuario,

        nombre:
          psicologo.nombre,

        correo:
          psicologo.correo,

        id_organizacion:
          idOrganizacion,

        estado:
          "activo",

        id_licencia:
          idLicencia

      }

    });


  } catch (error) {

    if (connection) {

      try {

        await connection.rollback();

      } catch {}

    }


    console.error(
      "❌ Error reactivando psicólogo:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al reactivar al psicólogo",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined

      });


  } finally {

    if (connection) {

      connection.release();

    }

  }

}