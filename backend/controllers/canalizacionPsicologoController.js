// ==================================================
// backend/controllers/canalizacionPsicologoController.js
// ==================================================

import pool from "../config/database.js";


// ==================================================
// AUXILIARES
// ==================================================

const enteroPositivo = valor => {

  const numero =
    Number(valor);


  return (
    Number.isInteger(numero) &&
    numero > 0
  )
    ? numero
    : null;

};


const normalizar = valor => {

  return valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";

};


// ==================================================
// OBTENER PSICÓLOGO AUTENTICADO
//
// REGLA:
// El perfil profesional SIEMPRE se resuelve por
// req.user.id_usuario.
//
// Si el token también trae id_psicologo, se valida
// que corresponda al mismo id_usuario.
// ==================================================

const obtenerPsicologoActual =
  async (
    req,
    connection = pool
  ) => {

    const idUsuario =
      enteroPositivo(
        req.user?.id_usuario
      );


    if (!idUsuario) {

      return null;

    }


    const idPsicologoToken =
      enteroPositivo(
        req.user?.id_psicologo
      );


    const parametros = [
      idUsuario
    ];


    let filtroPsicologoToken =
      "";


    if (
      idPsicologoToken
    ) {

      filtroPsicologoToken = `
        AND p.id_psicologo = ?
      `;


      parametros.push(
        idPsicologoToken
      );

    }


    const [rows] =
      await connection.query(
        `
          SELECT

            p.id_psicologo,
            p.id_usuario,
            p.especialidad,
            p.activo_canalizacion,
            p.estado_canalizacion,
            p.capacidad_maxima,

            (
              SELECT COUNT(*)

              FROM pacientes pa

              WHERE
                pa.id_psicologo =
                  p.id_psicologo
            )
              AS pacientes_activos,

            u.nombre,
            u.correo,
            u.rol

          FROM psicologos p

          INNER JOIN usuarios u
            ON u.id_usuario =
               p.id_usuario

          WHERE
            p.id_usuario = ?

            ${filtroPsicologoToken}

            AND LOWER(
              TRIM(
                COALESCE(
                  u.rol,
                  ''
                )
              )
            ) = 'psicologo'

          LIMIT 1
        `,
        parametros
      );


    return rows[0] || null;

  };


// ==================================================
// LISTAR MIS CANALIZACIONES
// ==================================================

export const listarMisCanalizacionesPsicologo =
async (req, res) => {

  try {

    const psicologo =
      await obtenerPsicologoActual(
        req
      );


    if (!psicologo) {

      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "Esta sección es exclusiva para psicólogos"

        });

    }


    const [rows] =
      await pool.query(
        `
          SELECT

            cp.id_opcion,

            cp.id_canalizacion,

            cp.fecha_seleccion,

            cp.estado_respuesta_profesional,

            cp.motivo_rechazo_profesional,

            cp.observacion_respuesta_profesional,

            cp.fecha_respuesta_profesional,


            c.motivo,

            c.modalidad_atencion_preferida,


            CASE

              WHEN
                cp.estado_respuesta_profesional =
                'aceptada'

              THEN e.telefono

              ELSE NULL

            END
              AS telefono,


            CASE

              WHEN
                cp.estado_respuesta_profesional =
                'aceptada'

              THEN e.correo

              ELSE NULL

            END
              AS correo


          FROM canalizacion_profesionales cp


          INNER JOIN canalizaciones c

            ON c.id_canalizacion =
               cp.id_canalizacion


          INNER JOIN empleados e

            ON e.id_empleado =
               c.id_empleado


          WHERE

            cp.tipo_profesional =
              'mirrorsoul'


            AND cp.id_psicologo = ?


            AND cp.enviado = 1


            AND
            (

              cp.seleccionado = 1

              OR

              c.id_opcion_elegida =
                cp.id_opcion

            )


          ORDER BY

            CASE

              WHEN
                cp.estado_respuesta_profesional =
                'pendiente'

              THEN 0


              WHEN
                cp.estado_respuesta_profesional =
                'aceptada'

              THEN 1


              ELSE 2

            END,


            cp.fecha_seleccion DESC,

            cp.id_opcion DESC
        `,
        [
          psicologo.id_psicologo
        ]
      );


    const resultado =
      Array.isArray(rows)
        ? rows
        : [];


    const pendientes =
      resultado.filter(
        item => {

          const estado =
            item
              ?.estado_respuesta_profesional ||
            "pendiente";


          return (
            estado ===
            "pendiente"
          );

        }
      ).length;


    return res.json({

      success:
        true,


      psicologo: {

        id_psicologo:
          psicologo.id_psicologo,

        nombre:
          psicologo.nombre,

        especialidad:
          psicologo.especialidad,

        activo_canalizacion:
          Number(
            psicologo.activo_canalizacion
          ) === 1
            ? 1
            : 0,

        estado_canalizacion:
          psicologo.estado_canalizacion ||
          "disponible",

        pausa_temporal:
          psicologo.estado_canalizacion ===
            "pausa_temporal"
            ? 1
            : 0,

        capacidad_maxima:
          psicologo.capacidad_maxima !== null &&
          psicologo.capacidad_maxima !== undefined
            ? Number(
                psicologo.capacidad_maxima
              )
            : null,

        pacientes_activos:
          Number(
            psicologo.pacientes_activos
          ) || 0,

        cupos_disponibles:
          psicologo.capacidad_maxima !== null &&
          psicologo.capacidad_maxima !== undefined
            ? Math.max(
                Number(
                  psicologo.capacidad_maxima
                ) -
                (
                  Number(
                    psicologo.pacientes_activos
                  ) || 0
                ),
                0
              )
            : null

      },


      total:
        resultado.length,


      pendientes,


      canalizaciones:
        resultado

    });


  } catch (error) {

    console.error(
      "❌ Error listando canalizaciones del psicólogo:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "No fue posible obtener las canalizaciones recibidas"

      });

  }

};


// ==================================================
// ACEPTAR CANALIZACIÓN
// ==================================================

export const aceptarCanalizacionPsicologo =
async (req, res) => {

  let connection;


  try {

    const idOpcion =
      enteroPositivo(
        req.params.idOpcion
      );


    if (!idOpcion) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Solicitud de canalización inválida"

        });

    }


    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    const psicologo =
      await obtenerPsicologoActual(
        req,
        connection
      );


    if (!psicologo) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "Esta sección es exclusiva para psicólogos"

        });

    }


    const [rows] =
      await connection.query(
        `
          SELECT

            cp.id_opcion,

            cp.id_canalizacion,

            cp.id_psicologo,

            cp.tipo_profesional,

            cp.seleccionado,

            cp.estado_respuesta_profesional,


            c.id_opcion_elegida,

            c.estatus


          FROM canalizacion_profesionales cp


          INNER JOIN canalizaciones c

            ON c.id_canalizacion =
               cp.id_canalizacion


          WHERE

            cp.id_opcion = ?

            AND cp.id_psicologo = ?

            AND cp.tipo_profesional =
              'mirrorsoul'


          LIMIT 1

          FOR UPDATE
        `,
        [
          idOpcion,
          psicologo.id_psicologo
        ]
      );


    if (!rows.length) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "La canalización no pertenece a este psicólogo"

        });

    }


    const opcion =
      rows[0];


    if (
      Number(
        opcion.id_opcion_elegida
      ) !==
      Number(
        opcion.id_opcion
      )
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          message:
            "El empleado no tiene seleccionada esta opción"

        });

    }


    if (
      opcion
        .estado_respuesta_profesional ===
      "aceptada"
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          message:
            "Esta canalización ya fue aceptada"

        });

    }


    if (
      opcion
        .estado_respuesta_profesional ===
      "rechazada"
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          message:
            "Esta canalización ya fue rechazada"

        });

    }


    await connection.query(
      `
        UPDATE canalizacion_profesionales

        SET

          estado_respuesta_profesional =
            'aceptada',

          motivo_rechazo_profesional =
            NULL,

          observacion_respuesta_profesional =
            NULL,

          fecha_respuesta_profesional =
            NOW()

        WHERE
          id_opcion = ?
      `,
      [
        idOpcion
      ]
    );


    await connection.query(
      `
        UPDATE canalizaciones

        SET

          estatus =
            'profesional_acepto'

        WHERE
          id_canalizacion = ?
      `,
      [
        opcion.id_canalizacion
      ]
    );


    await connection.query(
      `
        INSERT INTO canalizacion_historial
        (
          id_canalizacion,
          id_usuario,
          evento,
          detalle,
          fecha_evento
        )

        VALUES
        (
          ?,
          ?,
          'Profesional aceptó la canalización',
          ?,
          NOW()
        )
      `,
      [
        opcion.id_canalizacion,

        psicologo.id_usuario,

        `Psicólogo: ${psicologo.nombre}`
      ]
    );


    await connection
      .commit();


    return res.json({

      success:
        true,

      message:
        "Canalización aceptada correctamente",

      estatus:
        "profesional_acepto"

    });


  } catch (error) {

    if (connection) {

      try {

        await connection
          .rollback();

      } catch {}

    }


    console.error(
      "❌ Error aceptando canalización:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "No fue posible aceptar la canalización"

      });


  } finally {

    if (connection) {

      connection
        .release();

    }

  }

};


// ==================================================
// RECHAZAR CANALIZACIÓN
// ==================================================

export const rechazarCanalizacionPsicologo =
async (req, res) => {

  let connection;


  try {

    const idOpcion =
      enteroPositivo(
        req.params.idOpcion
      );


    const motivo =
      normalizar(
        req.body
          ?.motivo_rechazo
      );


    const observacion =
      String(
        req.body
          ?.observacion ||
        ""
      ).trim() ||
      null;


    // ==================================================
    // DISPONIBILIDAD PROFESIONAL
    // ==================================================

    const estadoProfesional =
      normalizar(
        req.body
          ?.estado_profesional
      ) ||
      "disponible";


    const estadosPermitidos = [

      "disponible",

      "cupo_completo",

      "pausa_temporal",

      "no_disponible"

    ];


    if (
      !estadosPermitidos.includes(
        estadoProfesional
      )
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Estado profesional inválido"

        });

    }


    const capacidadRecibida =
      req.body
        ?.capacidad_maxima;


    const capacidadMaxima =
      capacidadRecibida === "" ||
      capacidadRecibida === null ||
      capacidadRecibida === undefined
        ? null
        : Number(
            capacidadRecibida
          );


    if (
      capacidadMaxima !== null &&
      (
        !Number.isInteger(
          capacidadMaxima
        ) ||
        capacidadMaxima <= 0
      )
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "La capacidad máxima debe ser mayor a 0"

        });

    }


    const motivosPermitidos = [

      "agenda_llena",

      "sin_disponibilidad_horario",

      "no_atiende_caso",

      "periodo_ausencia",

      "capacidad_maxima",

      "otro"

    ];


    if (!idOpcion) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Solicitud de canalización inválida"

        });

    }


    if (
      !motivosPermitidos
        .includes(
          motivo
        )
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Selecciona un motivo válido para rechazar la canalización"

        });

    }


    if (
      motivo ===
        "otro" &&
      !observacion
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Escribe el motivo del rechazo"

        });

    }


    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    const psicologo =
      await obtenerPsicologoActual(
        req,
        connection
      );


    if (!psicologo) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "Esta sección es exclusiva para psicólogos"

        });

    }


    const [rows] =
      await connection.query(
        `
          SELECT

            cp.id_opcion,

            cp.id_canalizacion,

            cp.id_psicologo,

            cp.tipo_profesional,

            cp.seleccionado,

            cp.estado_respuesta_profesional,


            c.id_opcion_elegida,

            c.estatus,


            p.id_usuario
              AS id_usuario_psicologo


          FROM canalizacion_profesionales cp


          INNER JOIN canalizaciones c

            ON c.id_canalizacion =
               cp.id_canalizacion


          INNER JOIN psicologos p

            ON p.id_psicologo =
               cp.id_psicologo


          WHERE

            cp.id_opcion = ?

            AND cp.id_psicologo = ?

            AND p.id_usuario = ?

            AND cp.tipo_profesional =
              'mirrorsoul'


          LIMIT 1

          FOR UPDATE
        `,
        [
          idOpcion,

          psicologo.id_psicologo,

          psicologo.id_usuario
        ]
      );


    if (!rows.length) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "La canalización no pertenece a este psicólogo"

        });

    }


    const opcion =
      rows[0];


    // ==================================================
    // VALIDAR IDENTIDAD DEL PROFESIONAL
    // ==================================================

    if (
      Number(
        opcion.id_psicologo
      ) !==
        Number(
          psicologo.id_psicologo
        ) ||

      Number(
        opcion.id_usuario_psicologo
      ) !==
        Number(
          psicologo.id_usuario
        )
    ) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "La canalización no corresponde al perfil profesional autenticado"

        });

    }


    if (
      Number(
        opcion.id_opcion_elegida
      ) !==
      Number(
        opcion.id_opcion
      )
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          message:
            "Esta opción ya no está seleccionada por el empleado"

        });

    }


    if (
      opcion
        .estado_respuesta_profesional ===
      "aceptada"
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          message:
            "Una canalización ya aceptada no puede rechazarse desde esta pantalla"

        });

    }


    if (
      opcion
        .estado_respuesta_profesional ===
      "rechazada"
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success:
            false,

          message:
            "Esta canalización ya fue rechazada"

        });

    }


    await connection.query(
      `
        UPDATE canalizacion_profesionales

        SET

          estado_respuesta_profesional =
            'rechazada',

          motivo_rechazo_profesional = ?,

          observacion_respuesta_profesional = ?,

          fecha_respuesta_profesional =
            NOW()

        WHERE
          id_opcion = ?
      `,
      [
        motivo,

        observacion,

        idOpcion
      ]
    );


    // ==================================================
    // ACTUALIZAR DISPONIBILIDAD DEL PSICÓLOGO
    // ==================================================

    const activoCanalizacion =
      estadoProfesional ===
        "disponible"
        ? 1
        : 0;


    await connection.query(
      `
        UPDATE psicologos

        SET

          estado_canalizacion = ?,

          activo_canalizacion = ?,

          capacidad_maxima =
            CASE

              WHEN ? IS NULL
                THEN capacidad_maxima

              ELSE ?

            END

        WHERE
          id_psicologo = ?

          AND id_usuario = ?
      `,
      [
        estadoProfesional,

        activoCanalizacion,

        capacidadMaxima,

        capacidadMaxima,

        opcion.id_psicologo,

        psicologo.id_usuario
      ]
    );


    // ==================================================
    // LIBERAR ELECCIÓN PARA QUE RH ENVÍE OTRAS
    // ==================================================

    await connection.query(
      `
        UPDATE canalizaciones

        SET

          estatus =
            'requiere_nuevas_opciones',

          id_opcion_elegida =
            NULL,

          fecha_eleccion =
            NULL

        WHERE
          id_canalizacion = ?
      `,
      [
        opcion.id_canalizacion
      ]
    );


    await connection.query(
      `
        INSERT INTO canalizacion_historial
        (
          id_canalizacion,
          id_usuario,
          evento,
          detalle,
          fecha_evento
        )

        VALUES
        (
          ?,
          ?,
          'Profesional rechazó la canalización',
          ?,
          NOW()
        )
      `,
      [
        opcion.id_canalizacion,

        psicologo.id_usuario,

        `Psicólogo: ${psicologo.nombre}. Motivo: ${motivo}${
          observacion
            ? `. Observación: ${observacion}`
            : ""
        }`
      ]
    );


    await connection
      .commit();


    return res.json({

      success:
        true,

      message:
        "Canalización rechazada. RH deberá enviar nuevas opciones.",

      estatus:
        "requiere_nuevas_opciones",

      notificar_rh:
        true,

      disponibilidad_profesional: {

        id_psicologo:
          opcion.id_psicologo,

        id_usuario:
          psicologo.id_usuario,

        estado:
          estadoProfesional,

        activo_canalizacion:
          activoCanalizacion,

        capacidad_maxima:
          capacidadMaxima

      }

    });


  } catch (error) {

    if (connection) {

      try {

        await connection
          .rollback();

      } catch {}

    }


    console.error(
      "❌ Error rechazando canalización:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "No fue posible rechazar la canalización"

      });


  } finally {

    if (connection) {

      connection
        .release();

    }

  }

};