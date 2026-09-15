// backend/controllers/sesionController.js

import pool from "../config/database.js";


// =====================================================
// OBTENER SESIONES DE UN PACIENTE
//
// SOLO CONSULTA.
// NO CREA SESIONES.
// =====================================================

export async function obtenerSesionesPaciente(req, res) {

  const { id_paciente } = req.params;

  try {

    if (!id_paciente) {

      return res.status(400).json({
        message: "Falta el ID del paciente"
      });

    }

    const idPaciente =
      Number(id_paciente);

    if (!Number.isInteger(idPaciente)) {

      return res.status(400).json({
        message: "ID de paciente inválido"
      });

    }


    const [sesiones] =
      await pool.query(
        `
        SELECT
          id_sesion,
          id_paciente,
          id_cita,
          fecha,
          fecha_fin,
          notas,
          link_videollamada,
          estado,

          ROW_NUMBER() OVER (
            PARTITION BY id_paciente
            ORDER BY fecha ASC, id_sesion ASC
          ) AS numero_sesion

        FROM sesiones

        WHERE id_paciente = ?

        ORDER BY fecha DESC, id_sesion DESC
        `,
        [idPaciente]
      );


    return res.json(
      sesiones || []
    );


  } catch (err) {

    console.error(
      "❌ Error al obtener sesiones:",
      err
    );

    return res.status(500).json({
      message:
        "Error al obtener sesiones"
    });

  }

}



// =====================================================
// CREAR SESIÓN MANUAL
//
// SE CONSERVA POR COMPATIBILIDAD.
//
// EL FLUJO PRINCIPAL DE VIDEOLLAMADA NO DEPENDE
// DE ESTA FUNCIÓN.
// =====================================================

export async function crearSesion(req, res) {

  const {
    id_paciente,
    id_cita,
    notas
  } = req.body;


  console.log(
    "📥 Backend recibió creación manual de sesión:",
    req.body
  );


  if (!id_paciente) {

    return res.status(400).json({
      message:
        "Falta el id del paciente"
    });

  }


  const idPaciente =
    Number(id_paciente);


  if (!Number.isInteger(idPaciente)) {

    return res.status(400).json({
      message:
        "ID de paciente inválido"
    });

  }


  try {

    // ===================================================
    // VALIDAR PACIENTE
    // ===================================================

    const [checkPaciente] =
      await pool.query(
        `
        SELECT
          id_paciente,
          nombre,
          id_mirror

        FROM pacientes

        WHERE id_paciente = ?
        `,
        [idPaciente]
      );


    if (
      checkPaciente.length === 0
    ) {

      return res.status(400).json({
        message:
          `❌ Paciente ${idPaciente} no existe en la BD`
      });

    }


    // ===================================================
    // NOTAS
    // ===================================================

    let textoNotas =
      notas ||
      "Sesión sin notas";


    // ===================================================
    // SI VIENE DESDE UNA CITA
    // ===================================================

    if (id_cita) {

      const idCita =
        Number(id_cita);


      if (!Number.isInteger(idCita)) {

        return res.status(400).json({
          message:
            "ID de cita inválido"
        });

      }


      const [cita] =
        await pool.query(
          `
          SELECT
            id_paciente,
            motivo,
            notas

          FROM citas

          WHERE id_cita = ?
          `,
          [idCita]
        );


      if (
        !cita.length
      ) {

        return res.status(400).json({
          message:
            `❌ Cita ${idCita} no existe`
        });

      }


      if (
        Number(cita[0].id_paciente) !==
        idPaciente
      ) {

        return res.status(400).json({
          message:
            "⚠️ El paciente no coincide con la cita"
        });

      }


      textoNotas =
        `Sesión desde cita - Motivo: ${
          cita[0].motivo || ""
        } ${
          cita[0].notas || ""
        }`;

    }


    // ===================================================
    // CREAR SESIÓN
    // ===================================================

    const [result] =
      await pool.query(
        `
        INSERT INTO sesiones
        (
          id_cita,
          id_paciente,
          notas,
          link_videollamada,
          estado
        )

        VALUES (?, ?, ?, ?, ?)
        `,
        [
          id_cita ?? null,
          idPaciente,
          textoNotas,
          null,
          "activa"
        ]
      );


    const idSesion =
      Number(
        result.insertId
      );


    // ===================================================
    // NÚMERO DE SESIÓN
    // ===================================================

    const [numero] =
      await pool.query(
        `
        SELECT
          COUNT(*) AS numero_sesion

        FROM sesiones

        WHERE id_paciente = ?

        AND id_sesion <= ?
        `,
        [
          idPaciente,
          idSesion
        ]
      );


    const numeroSesion =
      Number(
        numero[0]?.numero_sesion || 1
      );


    console.log(
      "🆕 Sesión creada manualmente:",
      {
        idSesion,
        idPaciente,
        numeroSesion
      }
    );


    return res.status(201).json({

      success:
        true,

      id_sesion:
        idSesion,

      id_paciente:
        idPaciente,

      numero_sesion:
        numeroSesion,

      message:
        "✅ Sesión creada correctamente"

    });


  } catch (err) {

    console.error(
      "❌ Error al crear sesión:",
      err
    );

    return res.status(500).json({
      message:
        "Error al crear sesión"
    });

  }

}



// =====================================================
// INICIAR VIDEOLLAMADA DE UN PACIENTE
//
// FLUJO PRINCIPAL:
//
// Expediente
//    ↓
// Videollamada
//    ↓
// POST /api/sesiones/iniciar/:id_paciente
//
// IMPORTANTE:
//
// Esta función está protegida contra solicitudes
// simultáneas.
//
// Si el frontend manda:
//
// POST /api/sesiones/iniciar/4
// POST /api/sesiones/iniciar/4
//
// al mismo tiempo:
//
// 1. La primera bloquea al paciente.
// 2. Busca sesión activa.
// 3. Si no existe, crea una.
// 4. Crea/reutiliza la sala.
// 5. Hace COMMIT.
// 6. La segunda petición continúa.
// 7. La segunda encuentra la sesión activa.
// 8. Reutiliza la misma sesión y sala.
//
// Resultado:
//
// UNA SESIÓN
// UNA SALA
//
// =====================================================

export async function iniciarVideollamadaPaciente(
  req,
  res
) {

  const {
    id_paciente
  } = req.params;


  let connection = null;


  try {

    // ===================================================
    // VALIDAR ID
    // ===================================================

    if (!id_paciente) {

      return res.status(400).json({
        message:
          "Falta el ID del paciente"
      });

    }


    const idPaciente =
      Number(id_paciente);


    if (!Number.isInteger(idPaciente)) {

      return res.status(400).json({
        message:
          "ID de paciente inválido"
      });

    }


    // ===================================================
    // OBTENER CONEXIÓN
    // ===================================================

    connection =
      await pool.getConnection();


    // ===================================================
    // INICIAR TRANSACCIÓN
    // ===================================================

    await connection.beginTransaction();


    // ===================================================
    // VALIDAR Y BLOQUEAR PACIENTE
    //
    // FOR UPDATE es la parte importante.
    //
    // Si llegan dos peticiones simultáneamente
    // para el mismo paciente, la segunda queda
    // esperando aquí.
    // ===================================================

    const [paciente] =
      await connection.query(
        `
        SELECT
          id_paciente,
          nombre,
          id_mirror

        FROM pacientes

        WHERE id_paciente = ?

        FOR UPDATE
        `,
        [idPaciente]
      );


    // ===================================================
    // PACIENTE NO EXISTE
    // ===================================================

    if (
      paciente.length === 0
    ) {

      await connection.rollback();

      connection.release();

      connection = null;


      return res.status(404).json({
        message:
          "Paciente no encontrado"
      });

    }


    // ===================================================
    // BUSCAR SESIÓN ACTIVA
    //
    // ESTA CONSULTA SE REALIZA DESPUÉS DEL BLOQUEO.
    //
    // Esto evita la condición:
    //
    // Petición A -> no encuentra sesión
    // Petición B -> no encuentra sesión
    // Petición A -> INSERT
    // Petición B -> INSERT
    //
    // Ahora la segunda petición esperará.
    // ===================================================

    const [sesionesActivas] =
      await connection.query(
        `
        SELECT
          id_sesion,
          id_paciente,
          estado,
          link_videollamada,
          fecha

        FROM sesiones

        WHERE id_paciente = ?

        AND (
          estado IS NULL
          OR estado <> 'finalizada'
        )

        ORDER BY id_sesion DESC

        LIMIT 1
        `,
        [idPaciente]
      );


    let idSesion;

    let sesionExistente =
      false;

    let linkActual =
      null;


    // ===================================================
    // REUTILIZAR SESIÓN ACTIVA
    // ===================================================

    if (
      sesionesActivas.length > 0
    ) {

      idSesion =
        Number(
          sesionesActivas[0].id_sesion
        );

      sesionExistente =
        true;

      linkActual =
        sesionesActivas[0].link_videollamada;


      console.log(
        "♻️ Reutilizando sesión activa:",
        {
          idSesion,
          idPaciente
        }
      );

    }


    // ===================================================
    // CREAR NUEVA SESIÓN
    //
    // SOLO ocurre si NO existe una sesión activa.
    // ===================================================

    else {

      const [result] =
        await connection.query(
          `
          INSERT INTO sesiones
          (
            id_cita,
            id_paciente,
            notas,
            link_videollamada,
            estado
          )

          VALUES (?, ?, ?, ?, ?)
          `,
          [
            null,
            idPaciente,
            "Sesión iniciada desde videollamada",
            null,
            "activa"
          ]
        );


      idSesion =
        Number(
          result.insertId
        );

      sesionExistente =
        false;

      linkActual =
        null;


      console.log(
        "🆕 Nueva sesión creada:",
        {
          idSesion,
          idPaciente
        }
      );

    }


    // ===================================================
    // NÚMERO DE SESIÓN
    // ===================================================

    const [numero] =
      await connection.query(
        `
        SELECT
          COUNT(*) AS numero_sesion

        FROM sesiones

        WHERE id_paciente = ?

        AND id_sesion <= ?
        `,
        [
          idPaciente,
          idSesion
        ]
      );


    const numeroSesion =
      Number(
        numero[0]?.numero_sesion || 1
      );


    // ===================================================
    // FRONTEND
    // ===================================================

    const frontendOrigin =
      process.env.FRONTEND_URL ||
      `http://${req.hostname}:5175`;


    let sala =
      null;

    let linkPsicologo =
      null;


    // ===================================================
    // VALIDAR SALA EXISTENTE
    //
    // FORMATO:
    //
    // sala-ID_SESION-ID_PACIENTE-TIMESTAMP
    //
    // Ejemplo:
    //
    // sala-5-4-1787588303455
    // ===================================================

    if (
      linkActual
    ) {

      const partesLink =
        linkActual
          .split("/")
          .filter(Boolean);


      const salaExistente =
        partesLink[
          partesLink.length - 1
        ];


      const partesSala =
        salaExistente
          ? salaExistente.split("-")
          : [];


      const salaValida =
        partesSala.length >= 4 &&
        partesSala[0] === "sala" &&
        Number(partesSala[1]) === idSesion &&
        Number(partesSala[2]) === idPaciente;


      if (
        salaValida
      ) {

        sala =
          salaExistente;


        linkPsicologo =
          `${frontendOrigin}/SalaVideollamada/${sala}`;


        console.log(
          "♻️ Reutilizando sala válida:",
          {
            idSesion,
            idPaciente,
            sala
          }
        );

      } else {

        console.warn(
          "⚠️ Sala antigua o incorrecta. Se generará una nueva:",
          {
            idSesion,
            idPaciente,
            salaAnterior:
              salaExistente
          }
        );

      }

    }


    // ===================================================
    // CREAR SALA NUEVA
    // ===================================================

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
          link_videollamada = ?

        WHERE id_sesion = ?
        `,
        [
          linkPsicologo,
          idSesion
        ]
      );


      console.log(
        "📹 Sala nueva creada/corregida:",
        {
          idSesion,
          idPaciente,
          sala
        }
      );

    }


    // ===================================================
    // LINK DEL PACIENTE
    // ===================================================

    const linkPaciente =
      `${frontendOrigin}/videollamada-paciente/${sala}`;


    // ===================================================
    // CONFIRMAR TRANSACCIÓN
    // ===================================================

    await connection.commit();


    // ===================================================
    // LIBERAR CONEXIÓN
    // ===================================================

    connection.release();

    connection = null;


    // ===================================================
    // RESPUESTA
    // ===================================================

    return res.json({

      success:
        true,

      existente:
        sesionExistente,

      id_sesion:
        idSesion,

      id_paciente:
        idPaciente,

      numero_sesion:
        numeroSesion,

      sala,

      link:
        linkPsicologo,

      link_psicologo:
        linkPsicologo,

      link_paciente:
        linkPaciente,

      paciente: {

        id_paciente:
          paciente[0].id_paciente,

        nombre:
          paciente[0].nombre,

        id_mirror:
          paciente[0].id_mirror

      },

      message:
        sesionExistente
          ? "✅ Sesión activa recuperada"
          : "✅ Sesión y sala creadas correctamente"

    });


  } catch (err) {

    // ===================================================
    // ROLLBACK
    // ===================================================

    if (
      connection
    ) {

      try {

        await connection.rollback();

      } catch (rollbackError) {

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


    return res.status(500).json({
      message:
        "Error al iniciar videollamada"
    });


  } finally {

    // ===================================================
    // LIBERAR CONEXIÓN
    // ===================================================

    if (
      connection
    ) {

      connection.release();

    }

  }

}



// =====================================================
// FINALIZAR SESIÓN
//
// Se ejecuta desde SalaVideollamada.jsx.
// =====================================================

export async function finalizarSesion(
  req,
  res
) {

  const {
    id
  } = req.params;


  try {

    if (!id) {

      return res.status(400).json({
        message:
          "Falta el ID de la sesión"
      });

    }


    const idSesion =
      Number(id);


    if (!Number.isInteger(idSesion)) {

      return res.status(400).json({
        message:
          "ID de sesión inválido"
      });

    }


    // ===================================================
    // BUSCAR SESIÓN
    // ===================================================

    const [sesion] =
      await pool.query(
        `
        SELECT
          id_sesion,
          id_paciente,
          estado

        FROM sesiones

        WHERE id_sesion = ?
        `,
        [idSesion]
      );


    if (
      !sesion.length
    ) {

      return res.status(404).json({
        message:
          "⚠️ Sesión no encontrada"
      });

    }


    // ===================================================
    // EVITAR FINALIZAR DOS VECES
    // ===================================================

    if (
      sesion[0].estado ===
      "finalizada"
    ) {

      return res.status(400).json({
        message:
          "⚠️ Esta sesión ya está finalizada"
      });

    }


    // ===================================================
    // FINALIZAR
    // ===================================================

    const [result] =
      await pool.query(
        `
        UPDATE sesiones

        SET
          estado = 'finalizada',
          fecha_fin = NOW()

        WHERE id_sesion = ?
        `,
        [idSesion]
      );


    if (
      result.affectedRows === 0
    ) {

      return res.status(404).json({
        message:
          "⚠️ Sesión no encontrada"
      });

    }


    const idPaciente =
      Number(
        sesion[0].id_paciente
      );


    console.log(
      "🛑 Sesión finalizada:",
      {
        idSesion,
        idPaciente
      }
    );


    return res.json({

      success:
        true,

      id_sesion:
        idSesion,

      id_paciente:
        idPaciente,

      message:
        "✅ Sesión finalizada correctamente"

    });


  } catch (err) {

    console.error(
      "❌ Error al finalizar sesión:",
      err
    );

    return res.status(500).json({
      message:
        "Error al finalizar sesión"
    });

  }

}



// =====================================================
// GENERAR / RECUPERAR LINK DE VIDEOLLAMADA
//
// ESTA FUNCIÓN TRABAJA SOBRE UNA SESIÓN YA EXISTENTE.
//
// NO CREA SESIONES.
//
// Si la sesión ya tiene una sala válida:
//      la reutiliza.
//
// Si no tiene sala:
//      genera una nueva.
// =====================================================

export async function generarLinkVideollamada(
  req,
  res
) {

  const {
    id
  } = req.params;


  try {

    if (!id) {

      return res.status(400).json({
        message:
          "Falta el ID de la sesión"
      });

    }


    const idSesion =
      Number(id);


    if (!Number.isInteger(idSesion)) {

      return res.status(400).json({
        message:
          "ID de sesión inválido"
      });

    }


    // ===================================================
    // BUSCAR SESIÓN
    // ===================================================

    const [sesion] =
      await pool.query(
        `
        SELECT
          id_sesion,
          id_paciente,
          estado,
          link_videollamada

        FROM sesiones

        WHERE id_sesion = ?
        `,
        [idSesion]
      );


    if (
      !sesion.length
    ) {

      return res.status(404).json({
        message:
          "⚠️ Sesión no encontrada"
      });

    }


    const idPaciente =
      Number(
        sesion[0].id_paciente
      );


    // ===================================================
    // NO USAR SESIONES FINALIZADAS
    // ===================================================

    if (
      sesion[0].estado ===
      "finalizada"
    ) {

      return res.status(400).json({
        message:
          "⚠️ Esta sesión ya está finalizada"
      });

    }


    // ===================================================
    // NÚMERO DE SESIÓN
    // ===================================================

    const [numero] =
      await pool.query(
        `
        SELECT
          COUNT(*) AS numero_sesion

        FROM sesiones

        WHERE id_paciente = ?

        AND id_sesion <= ?
        `,
        [
          idPaciente,
          idSesion
        ]
      );


    const numeroSesion =
      Number(
        numero[0]?.numero_sesion || 1
      );


    // ===================================================
    // FRONTEND
    // ===================================================

    const frontendOrigin =
      process.env.FRONTEND_URL ||
      `http://${req.hostname}:5175`;


    // ===================================================
    // SI YA EXISTE LINK
    // ===================================================

    if (
      sesion[0].link_videollamada
    ) {

      const linkPsicologo =
        sesion[0].link_videollamada;


      const partesLink =
        linkPsicologo
          .split("/")
          .filter(Boolean);


      const sala =
        partesLink[
          partesLink.length - 1
        ];


      // =================================================
      // VALIDAR SALA
      // =================================================

      const partesSala =
        sala
          ? sala.split("-")
          : [];


      const salaValida =
        partesSala.length >= 4 &&
        partesSala[0] === "sala" &&
        Number(partesSala[1]) === idSesion &&
        Number(partesSala[2]) === idPaciente;


      if (
        salaValida
      ) {

        const linkPaciente =
          `${frontendOrigin}/videollamada-paciente/${sala}`;


        console.log(
          "♻️ Sala existente recuperada:",
          {
            idSesion,
            idPaciente,
            sala
          }
        );


        return res.json({

          success:
            true,

          existente:
            true,

          id_sesion:
            idSesion,

          id_paciente:
            idPaciente,

          numero_sesion:
            numeroSesion,

          sala,

          link:
            linkPsicologo,

          link_psicologo:
            linkPsicologo,

          link_paciente:
            linkPaciente,

          message:
            "✅ La sala existente fue recuperada"

        });

      }

    }


    // ===================================================
    // CREAR NUEVA SALA
    // ===================================================

    const sala =
      `sala-${idSesion}-${idPaciente}-${Date.now()}`;


    const linkPsicologo =
      `${frontendOrigin}/SalaVideollamada/${sala}`;


    const linkPaciente =
      `${frontendOrigin}/videollamada-paciente/${sala}`;


    // ===================================================
    // GUARDAR LINK DEL PSICÓLOGO
    // ===================================================

    await pool.query(
      `
      UPDATE sesiones

      SET
        link_videollamada = ?

      WHERE id_sesion = ?
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
        idPaciente,
        sala
      }
    );


    // ===================================================
    // RESPUESTA
    // ===================================================

    return res.json({

      success:
        true,

      existente:
        false,

      id_sesion:
        idSesion,

      id_paciente:
        idPaciente,

      numero_sesion:
        numeroSesion,

      sala,

      link:
        linkPsicologo,

      link_psicologo:
        linkPsicologo,

      link_paciente:
        linkPaciente,

      message:
        "✅ Link generado correctamente"

    });


  } catch (err) {

    console.error(
      "❌ Error al generar link de videollamada:",
      err
    );

    return res.status(500).json({
      message:
        "Error al generar link de videollamada"
    });

  }

}