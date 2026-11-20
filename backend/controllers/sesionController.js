import pool from "../config/database.js";

/* ==================================================
   OBTENER SESIONES DEL PACIENTE
================================================== */
export async function obtenerSesionesPaciente(req, res) {

  const {
    id_paciente
  } = req.params;

  try {

    if (!id_paciente) {

      return res
        .status(400)
        .json({
          message:
            "Falta el ID del paciente"
        });

    }


    const idPaciente =
      Number(
        id_paciente
      );


    if (
      !Number.isInteger(
        idPaciente
      ) ||
      idPaciente <= 0
    ) {

      return res
        .status(400)
        .json({
          message:
            "ID de paciente inválido"
        });

    }


    const [sesiones] =
      await pool.query(
        `
          SELECT
            id_sesion,
            id_paciente,
            numero_sesion,
            id_cita,
            modalidad,
            fecha,
            fecha_fin,
            notas,
            link_videollamada,
            estado
          FROM sesiones
          WHERE id_paciente = ?
          ORDER BY
            numero_sesion DESC,
            fecha DESC,
            id_sesion DESC
        `,
        [
          idPaciente
        ]
      );


    return res.json(
      sesiones || []
    );


  } catch (err) {

    console.error(
      "❌ Error al obtener sesiones:",
      err
    );


    return res
      .status(500)
      .json({
        message:
          "Error al obtener sesiones"
      });

  }

}


/* ==================================================
   CREAR SESIÓN
================================================== */
export async function crearSesion(req, res) {

  const {
    id_paciente,
    id_cita,
    modalidad = "presencial",
    notas
  } = req.body;


  console.log(
    "📥 Backend recibió creación de sesión:",
    req.body
  );


  if (!id_paciente) {

    return res
      .status(400)
      .json({
        message:
          "Falta el ID del paciente"
      });

  }


  const idPaciente =
    Number(
      id_paciente
    );


  if (
    !Number.isInteger(
      idPaciente
    ) ||
    idPaciente <= 0
  ) {

    return res
      .status(400)
      .json({
        message:
          "ID de paciente inválido"
      });

  }


  const modalidadNormalizada =
    String(
      modalidad
    )
      .trim()
      .toLowerCase();


  const modalidadesPermitidas = [
    "presencial",
    "videollamada"
  ];


  if (
    !modalidadesPermitidas.includes(
      modalidadNormalizada
    )
  ) {

    return res
      .status(400)
      .json({
        message:
          "Modalidad inválida. Debe ser presencial o videollamada."
      });

  }


  let connection =
    null;


  try {

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    /* ==================================================
       VALIDAR PACIENTE
    ================================================== */

    const [checkPaciente] =
      await connection.query(
        `
          SELECT
            id_paciente,
            nombre,
            id_mirror
          FROM pacientes
          WHERE id_paciente = ?
          LIMIT 1
          FOR UPDATE
        `,
        [
          idPaciente
        ]
      );


    if (
      checkPaciente.length === 0
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({
          message:
            `❌ Paciente ${idPaciente} no existe en la BD`
        });

    }


    /* ==================================================
       BLOQUEAR SEGUNDA SESIÓN ACTIVA
    ================================================== */

    const [sesionesActivas] =
      await connection.query(
        `
          SELECT
            id_sesion,
            numero_sesion
          FROM sesiones
          WHERE id_paciente = ?
            AND estado = 'activa'
          ORDER BY
            fecha DESC,
            id_sesion DESC
          LIMIT 1
          FOR UPDATE
        `,
        [
          idPaciente
        ]
      );


    if (
      sesionesActivas.length > 0
    ) {

      await connection
        .rollback();


      const sesionActiva =
        sesionesActivas[0];


      return res
        .status(409)
        .json({
          success: false,

          message:
            `⚠️ Este paciente ya tiene la sesión #${sesionActiva.numero_sesion || sesionActiva.id_sesion} activa. Finalízala antes de crear otra.`,

          id_sesion_activa:
            Number(
              sesionActiva
                .id_sesion
            ),

          numero_sesion_activa:
            Number(
              sesionActiva
                .numero_sesion ||
              0
            ) || null
        });

    }


    /* ==================================================
       CALCULAR SIGUIENTE NÚMERO DE SESIÓN
       CONSECUTIVO POR PACIENTE
    ================================================== */

    const [numeroRows] =
      await connection.query(
        `
          SELECT
            COALESCE(
              MAX(numero_sesion),
              0
            ) + 1 AS siguiente_numero
          FROM sesiones
          WHERE id_paciente = ?
          FOR UPDATE
        `,
        [
          idPaciente
        ]
      );


    const numeroSesion =
      Number(
        numeroRows[0]
          ?.siguiente_numero ||
        1
      );


    /* ==================================================
       NOTAS
    ================================================== */

    let textoNotas =
      notas ||
      (
        modalidadNormalizada ===
        "videollamada"

          ? "Sesión por videollamada"

          : "Sesión presencial"
      );


    /* ==================================================
       VALIDAR CITA SI EXISTE
    ================================================== */

    let idCitaFinal =
      null;


    if (id_cita) {

      const idCita =
        Number(
          id_cita
        );


      if (
        !Number.isInteger(
          idCita
        ) ||
        idCita <= 0
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({
            message:
              "ID de cita inválido"
          });

      }


      const [cita] =
        await connection.query(
          `
            SELECT
              id_paciente,
              motivo,
              notas
            FROM citas
            WHERE id_cita = ?
            LIMIT 1
          `,
          [
            idCita
          ]
        );


      if (
        !cita.length
      ) {

        await connection
          .rollback();


        return res
          .status(404)
          .json({
            message:
              `❌ Cita ${idCita} no existe`
          });

      }


      if (
        Number(
          cita[0]
            .id_paciente
        ) !==
        idPaciente
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({
            message:
              "⚠️ El paciente no coincide con la cita"
          });

      }


      idCitaFinal =
        idCita;


      if (!notas) {

        textoNotas =
          `Sesión desde cita - Motivo: ${cita[0].motivo || ""} ${cita[0].notas || ""}`
            .trim();

      }

    }


    /* ==================================================
       CREAR SESIÓN
    ================================================== */

    const [result] =
      await connection.query(
        `
          INSERT INTO sesiones
          (
            id_cita,
            id_paciente,
            numero_sesion,
            modalidad,
            notas,
            link_videollamada,
            estado
          )
          VALUES
          (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
          )
        `,
        [
          idCitaFinal,
          idPaciente,
          numeroSesion,
          modalidadNormalizada,
          textoNotas,
          null,
          "activa"
        ]
      );


    const idSesion =
      Number(
        result.insertId
      );


    await connection
      .commit();


    console.log(
      "🆕 Nueva sesión clínica creada:",
      {
        idSesion,
        idPaciente,
        numeroSesion,
        modalidad:
          modalidadNormalizada
      }
    );


    return res
      .status(201)
      .json({
        success: true,

        id_sesion:
          idSesion,

        id_paciente:
          idPaciente,

        numero_sesion:
          numeroSesion,

        modalidad:
          modalidadNormalizada,

        estado:
          "activa",

        paciente: {

          id_paciente:
            checkPaciente[0]
              .id_paciente,

          nombre:
            checkPaciente[0]
              .nombre,

          id_mirror:
            checkPaciente[0]
              .id_mirror

        },

        message:
          `✅ Sesión ${numeroSesion} creada correctamente`
      });


  } catch (err) {

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      } catch (
        rollbackError
      ) {

        console.error(
          "❌ Error haciendo rollback:",
          rollbackError
        );

      }

    }


    console.error(
      "❌ Error al crear sesión:",
      err
    );


    return res
      .status(500)
      .json({
        message:
          "Error al crear sesión",

        error:
          process.env.NODE_ENV ===
          "development"
            ? err.message
            : undefined
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


/* ==================================================
   INICIAR VIDEOLLAMADA DEL PACIENTE

   IMPORTANTE:

   ESTA FUNCIÓN NO CREA SESIONES.

   La sesión debe crearse primero desde:

   Sesiones
   → Nueva sesión
   → Videollamada

   Después esta función únicamente genera
   o reutiliza la sala.
================================================== */
export async function iniciarVideollamadaPaciente(
  req,
  res
) {

  const {
    id_paciente
  } = req.params;


  let connection =
    null;


  try {

    if (!id_paciente) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "Falta el ID del paciente"
        });

    }


    const idPaciente =
      Number(
        id_paciente
      );


    if (
      !Number.isInteger(
        idPaciente
      ) ||
      idPaciente <= 0
    ) {

      return res
        .status(400)
        .json({
          success: false,

          message:
            "ID de paciente inválido"
        });

    }


    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    /* ==================================================
       PACIENTE
    ================================================== */

    const [paciente] =
      await connection.query(
        `
          SELECT
            id_paciente,
            nombre,
            id_mirror
          FROM pacientes
          WHERE id_paciente = ?
          LIMIT 1
          FOR UPDATE
        `,
        [
          idPaciente
        ]
      );


    if (
      paciente.length === 0
    ) {

      await connection
        .rollback();


      return res
        .status(404)
        .json({
          success: false,

          message:
            "Paciente no encontrado"
        });

    }


    /* ==================================================
       BUSCAR SESIÓN ACTIVA
       YA NO SE CREA SESIÓN AQUÍ
    ================================================== */

    const [sesionesActivas] =
      await connection.query(
        `
          SELECT
            id_sesion,
            id_paciente,
            numero_sesion,
            modalidad,
            estado,
            link_videollamada,
            fecha
          FROM sesiones
          WHERE id_paciente = ?
            AND estado = 'activa'
          ORDER BY
            fecha DESC,
            id_sesion DESC
          LIMIT 1
          FOR UPDATE
        `,
        [
          idPaciente
        ]
      );


    if (
      !sesionesActivas.length
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({
          success: false,

          code:
            "SIN_SESION_ACTIVA",

          message:
            "Primero inicia una sesión clínica desde el módulo Sesiones antes de abrir la videollamada."
        });

    }


    const sesionActiva =
      sesionesActivas[0];


    const idSesion =
      Number(
        sesionActiva
          .id_sesion
      );


    const numeroSesion =
      Number(
        sesionActiva
          .numero_sesion ||
        1
      );


    const linkActual =
      sesionActiva
        .link_videollamada ||
      null;


    /* ==================================================
       CAMBIAR MODALIDAD A VIDEOLLAMADA
       SIN CREAR OTRA SESIÓN
    ================================================== */

    if (
      String(
        sesionActiva
          .modalidad ||
        ""
      )
        .trim()
        .toLowerCase() !==
      "videollamada"
    ) {

      await connection.query(
        `
          UPDATE sesiones
          SET
            modalidad = 'videollamada'
          WHERE id_sesion = ?
            AND estado = 'activa'
        `,
        [
          idSesion
        ]
      );

    }


    /* ==================================================
       URL FRONTEND
    ================================================== */

    const frontendOrigin =
      process.env.FRONTEND_URL ||
      `http://${req.hostname}:5175`;


    let sala =
      null;


    let linkPsicologo =
      null;


    /* ==================================================
       REUTILIZAR SALA EXISTENTE
    ================================================== */

    if (
      linkActual
    ) {

      const partesLink =
        String(
          linkActual
        )
          .split("/")
          .filter(
            Boolean
          );


      const salaExistente =
        partesLink[
          partesLink.length - 1
        ];


      const partesSala =
        salaExistente
          ? salaExistente
              .split("-")
          : [];


      const salaValida =
        partesSala.length >= 4 &&

        partesSala[0] ===
          "sala" &&

        Number(
          partesSala[1]
        ) ===
          idSesion &&

        Number(
          partesSala[2]
        ) ===
          idPaciente;


      if (
        salaValida
      ) {

        sala =
          salaExistente;


        linkPsicologo =
          `${frontendOrigin}/SalaVideollamada/${sala}`;


        console.log(
          "♻️ Reutilizando sala de sesión activa:",
          {
            idSesion,
            numeroSesion,
            idPaciente,
            sala
          }
        );

      }

    }


    /* ==================================================
       CREAR SALA
       SOLO SALA, NO SESIÓN
    ================================================== */

    if (
      !sala
    ) {

      sala =
        `sala-${idSesion}-${idPaciente}-${Date.now()}`;


      linkPsicologo =
        `${frontendOrigin}/SalaVideollamada/${sala}`;


      await connection.query(
        `
          UPDATE sesiones
          SET
            modalidad = 'videollamada',
            link_videollamada = ?
          WHERE id_sesion = ?
            AND estado = 'activa'
        `,
        [
          linkPsicologo,
          idSesion
        ]
      );


      console.log(
        "📹 Sala creada sobre sesión activa:",
        {
          idSesion,
          numeroSesion,
          idPaciente,
          sala
        }
      );

    }


    const linkPaciente =
      `${frontendOrigin}/videollamada-paciente/${sala}`;


    await connection
      .commit();


    return res.json({
      success: true,

      existente:
        true,

      id_sesion:
        idSesion,

      id_paciente:
        idPaciente,

      numero_sesion:
        numeroSesion,

      modalidad:
        "videollamada",

      estado:
        "activa",

      sala,

      link:
        linkPsicologo,

      link_psicologo:
        linkPsicologo,

      link_paciente:
        linkPaciente,

      paciente: {

        id_paciente:
          paciente[0]
            .id_paciente,

        nombre:
          paciente[0]
            .nombre,

        id_mirror:
          paciente[0]
            .id_mirror

      },

      message:
        `✅ Videollamada preparada para la sesión ${numeroSesion}`
    });


  } catch (err) {

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      } catch (
        rollbackError
      ) {

        console.error(
          "❌ Error haciendo rollback:",
          rollbackError
        );

      }

    }


    console.error(
      "❌ Error al iniciar videollamada:",
      err
    );


    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error al iniciar videollamada",

        error:
          process.env.NODE_ENV ===
          "development"
            ? err.message
            : undefined
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


/* ==================================================
   FINALIZAR SESIÓN
================================================== */
export async function finalizarSesion(
  req,
  res
) {

  const {
    id
  } = req.params;


  try {

    if (!id) {

      return res
        .status(400)
        .json({
          message:
            "Falta el ID de la sesión"
        });

    }


    const idSesion =
      Number(
        id
      );


    if (
      !Number.isInteger(
        idSesion
      ) ||
      idSesion <= 0
    ) {

      return res
        .status(400)
        .json({
          message:
            "ID de sesión inválido"
        });

    }


    const [sesion] =
      await pool.query(
        `
          SELECT
            id_sesion,
            id_paciente,
            numero_sesion,
            modalidad,
            estado
          FROM sesiones
          WHERE id_sesion = ?
          LIMIT 1
        `,
        [
          idSesion
        ]
      );


    if (
      !sesion.length
    ) {

      return res
        .status(404)
        .json({
          message:
            "⚠️ Sesión no encontrada"
        });

    }


    if (
      sesion[0]
        .estado ===
      "finalizada"
    ) {

      return res
        .status(400)
        .json({
          message:
            "⚠️ Esta sesión ya está finalizada"
        });

    }


    const [result] =
      await pool.query(
        `
          UPDATE sesiones
          SET
            estado = 'finalizada',
            fecha_fin = NOW()
          WHERE id_sesion = ?
        `,
        [
          idSesion
        ]
      );


    if (
      result.affectedRows === 0
    ) {

      return res
        .status(404)
        .json({
          message:
            "⚠️ Sesión no encontrada"
        });

    }


    const idPaciente =
      Number(
        sesion[0]
          .id_paciente
      );


    const numeroSesion =
      Number(
        sesion[0]
          .numero_sesion ||
        1
      );


    console.log(
      "🛑 Sesión finalizada:",
      {
        idSesion,
        numeroSesion,
        idPaciente,
        modalidad:
          sesion[0]
            .modalidad
      }
    );


    return res.json({
      success: true,

      id_sesion:
        idSesion,

      id_paciente:
        idPaciente,

      numero_sesion:
        numeroSesion,

      modalidad:
        sesion[0]
          .modalidad,

      estado:
        "finalizada",

      message:
        `✅ Sesión ${numeroSesion} finalizada correctamente`
    });


  } catch (err) {

    console.error(
      "❌ Error al finalizar sesión:",
      err
    );


    return res
      .status(500)
      .json({
        message:
          "Error al finalizar sesión"
      });

  }

}


/* ==================================================
   GENERAR LINK DE VIDEOLLAMADA
   SOBRE UNA SESIÓN YA EXISTENTE
================================================== */
export async function generarLinkVideollamada(
  req,
  res
) {

  const {
    id
  } = req.params;


  try {

    if (!id) {

      return res
        .status(400)
        .json({
          message:
            "Falta el ID de la sesión"
        });

    }


    const idSesion =
      Number(
        id
      );


    if (
      !Number.isInteger(
        idSesion
      ) ||
      idSesion <= 0
    ) {

      return res
        .status(400)
        .json({
          message:
            "ID de sesión inválido"
        });

    }


    const [sesion] =
      await pool.query(
        `
          SELECT
            id_sesion,
            id_paciente,
            numero_sesion,
            modalidad,
            estado,
            link_videollamada
          FROM sesiones
          WHERE id_sesion = ?
          LIMIT 1
        `,
        [
          idSesion
        ]
      );


    if (
      !sesion.length
    ) {

      return res
        .status(404)
        .json({
          message:
            "⚠️ Sesión no encontrada"
        });

    }


    const idPaciente =
      Number(
        sesion[0]
          .id_paciente
      );


    const numeroSesion =
      Number(
        sesion[0]
          .numero_sesion ||
        1
      );


    if (
      sesion[0]
        .estado ===
      "finalizada"
    ) {

      return res
        .status(400)
        .json({
          message:
            "⚠️ Esta sesión ya está finalizada"
        });

    }


    if (
      sesion[0]
        .estado !==
      "activa"
    ) {

      return res
        .status(409)
        .json({
          success: false,

          message:
            "La videollamada solo puede abrirse sobre una sesión activa."
        });

    }


    if (
      String(
        sesion[0]
          .modalidad ||
        ""
      )
        .trim()
        .toLowerCase() !==
      "videollamada"
    ) {

      await pool.query(
        `
          UPDATE sesiones
          SET
            modalidad = 'videollamada'
          WHERE id_sesion = ?
            AND estado = 'activa'
        `,
        [
          idSesion
        ]
      );

    }


    const frontendOrigin =
      process.env.FRONTEND_URL ||
      `http://${req.hostname}:5175`;


    /* ==================================================
       REUTILIZAR SALA EXISTENTE
    ================================================== */

    if (
      sesion[0]
        .link_videollamada
    ) {

      const linkPsicologo =
        sesion[0]
          .link_videollamada;


      const partesLink =
        linkPsicologo
          .split("/")
          .filter(
            Boolean
          );


      const sala =
        partesLink[
          partesLink.length - 1
        ];


      const partesSala =
        sala
          ? sala.split("-")
          : [];


      const salaValida =
        partesSala.length >= 4 &&

        partesSala[0] ===
          "sala" &&

        Number(
          partesSala[1]
        ) ===
          idSesion &&

        Number(
          partesSala[2]
        ) ===
          idPaciente;


      if (
        salaValida
      ) {

        const linkPaciente =
          `${frontendOrigin}/videollamada-paciente/${sala}`;


        console.log(
          "♻️ Sala existente recuperada:",
          {
            idSesion,
            numeroSesion,
            idPaciente,
            sala
          }
        );


        return res.json({
          success: true,

          existente:
            true,

          id_sesion:
            idSesion,

          id_paciente:
            idPaciente,

          numero_sesion:
            numeroSesion,

          modalidad:
            "videollamada",

          sala,

          link:
            linkPsicologo,

          link_psicologo:
            linkPsicologo,

          link_paciente:
            linkPaciente,

          message:
            `✅ Sala existente de la sesión ${numeroSesion} recuperada`
        });

      }

    }


    /* ==================================================
       CREAR NUEVA SALA
       SOBRE SESIÓN EXISTENTE
    ================================================== */

    const sala =
      `sala-${idSesion}-${idPaciente}-${Date.now()}`;


    const linkPsicologo =
      `${frontendOrigin}/SalaVideollamada/${sala}`;


    const linkPaciente =
      `${frontendOrigin}/videollamada-paciente/${sala}`;


    await pool.query(
      `
        UPDATE sesiones
        SET
          modalidad = 'videollamada',
          link_videollamada = ?
        WHERE id_sesion = ?
          AND estado = 'activa'
      `,
      [
        linkPsicologo,
        idSesion
      ]
    );


    console.log(
      "📹 Link de videollamada generado:",
      {
        idSesion,
        numeroSesion,
        idPaciente,
        sala
      }
    );


    return res.json({
      success: true,

      existente:
        false,

      id_sesion:
        idSesion,

      id_paciente:
        idPaciente,

      numero_sesion:
        numeroSesion,

      modalidad:
        "videollamada",

      sala,

      link:
        linkPsicologo,

      link_psicologo:
        linkPsicologo,

      link_paciente:
        linkPaciente,

      message:
        `✅ Link generado para la sesión ${numeroSesion}`
    });


  } catch (err) {

    console.error(
      "❌ Error al generar link de videollamada:",
      err
    );


    return res
      .status(500)
      .json({
        message:
          "Error al generar link de videollamada"
      });

  }

}