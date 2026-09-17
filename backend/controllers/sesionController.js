import pool from "../config/database.js";

/* ==================================================
   OBTENER SESIONES DEL PACIENTE
================================================== */
export async function obtenerSesionesPaciente(req, res) {
  const { id_paciente } = req.params;

  try {
    if (!id_paciente) return res.status(400).json({ message: "Falta el ID del paciente" });

    const idPaciente = Number(id_paciente);
    if (!Number.isInteger(idPaciente)) {
      return res.status(400).json({ message: "ID de paciente inválido" });
    }

    const [sesiones] = await pool.query(`
      SELECT
        id_sesion,
        id_paciente,
        id_cita,
        modalidad,
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
    `, [idPaciente]);

    return res.json(sesiones || []);
  } catch (err) {
    console.error("❌ Error al obtener sesiones:", err);
    return res.status(500).json({ message: "Error al obtener sesiones" });
  }
}

/* ==================================================
   CREAR SESIÓN
================================================== */
export async function crearSesion(req, res) {
  const { id_paciente, id_cita, modalidad = "presencial", notas } = req.body;

  console.log("📥 Backend recibió creación de sesión:", req.body);

  if (!id_paciente) return res.status(400).json({ message: "Falta el ID del paciente" });

  const idPaciente = Number(id_paciente);
  if (!Number.isInteger(idPaciente)) {
    return res.status(400).json({ message: "ID de paciente inválido" });
  }

  const modalidadNormalizada = String(modalidad).trim().toLowerCase();
  const modalidadesPermitidas = ["presencial", "videollamada"];

  if (!modalidadesPermitidas.includes(modalidadNormalizada)) {
    return res.status(400).json({
      message: "Modalidad inválida. Debe ser presencial o videollamada."
    });
  }

  try {
    const [checkPaciente] = await pool.query(`
      SELECT id_paciente, nombre, id_mirror
      FROM pacientes
      WHERE id_paciente = ?
    `, [idPaciente]);

    if (checkPaciente.length === 0) {
      return res.status(404).json({
        message: `❌ Paciente ${idPaciente} no existe en la BD`
      });
    }

    /* ==================================================
       BLOQUEAR SEGUNDA SESIÓN ACTIVA
    ================================================== */
    const [sesionesActivas] = await pool.query(`
      SELECT id_sesion
      FROM sesiones
      WHERE id_paciente = ?
        AND estado = 'activa'
      ORDER BY fecha DESC, id_sesion DESC
      LIMIT 1
    `, [idPaciente]);

    if (sesionesActivas.length > 0) {
      return res.status(409).json({
        success: false,
        message: `⚠️ Este paciente ya tiene una sesión activa (#${sesionesActivas[0].id_sesion}). Finalízala antes de crear otra.`,
        id_sesion_activa: Number(sesionesActivas[0].id_sesion)
      });
    }

    let textoNotas = notas || (
      modalidadNormalizada === "videollamada"
        ? "Sesión por videollamada"
        : "Sesión presencial"
    );

    let idCitaFinal = null;

    if (id_cita) {
      const idCita = Number(id_cita);

      if (!Number.isInteger(idCita)) {
        return res.status(400).json({ message: "ID de cita inválido" });
      }

      const [cita] = await pool.query(`
        SELECT id_paciente, motivo, notas
        FROM citas
        WHERE id_cita = ?
      `, [idCita]);

      if (!cita.length) {
        return res.status(404).json({ message: `❌ Cita ${idCita} no existe` });
      }

      if (Number(cita[0].id_paciente) !== idPaciente) {
        return res.status(400).json({
          message: "⚠️ El paciente no coincide con la cita"
        });
      }

      idCitaFinal = idCita;

      if (!notas) {
        textoNotas = `Sesión desde cita - Motivo: ${cita[0].motivo || ""} ${cita[0].notas || ""}`;
      }
    }

    const [result] = await pool.query(`
      INSERT INTO sesiones
        (id_cita, id_paciente, modalidad, notas, link_videollamada, estado)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [
      idCitaFinal,
      idPaciente,
      modalidadNormalizada,
      textoNotas,
      null,
      "activa"
    ]);

    const idSesion = Number(result.insertId);

    const [numero] = await pool.query(`
      SELECT COUNT(*) AS numero_sesion
      FROM sesiones
      WHERE id_paciente = ?
        AND id_sesion <= ?
    `, [idPaciente, idSesion]);

    const numeroSesion = Number(numero[0]?.numero_sesion || 1);

    console.log("🆕 Nueva sesión clínica creada:", {
      idSesion,
      idPaciente,
      numeroSesion,
      modalidad: modalidadNormalizada
    });

    return res.status(201).json({
      success: true,
      id_sesion: idSesion,
      id_paciente: idPaciente,
      numero_sesion: numeroSesion,
      modalidad: modalidadNormalizada,
      estado: "activa",
      paciente: {
        id_paciente: checkPaciente[0].id_paciente,
        nombre: checkPaciente[0].nombre,
        id_mirror: checkPaciente[0].id_mirror
      },
      message: `✅ Sesión ${numeroSesion} creada correctamente`
    });

  } catch (err) {
    console.error("❌ Error al crear sesión:", err);
    return res.status(500).json({ message: "Error al crear sesión" });
  }
}

/* ==================================================
   INICIAR VIDEOLLAMADA DEL PACIENTE
   Se conserva para compatibilidad con flujo anterior
================================================== */
export async function iniciarVideollamadaPaciente(req, res) {
  const { id_paciente } = req.params;
  let connection = null;

  try {
    if (!id_paciente) {
      return res.status(400).json({ message: "Falta el ID del paciente" });
    }

    const idPaciente = Number(id_paciente);
    if (!Number.isInteger(idPaciente)) {
      return res.status(400).json({ message: "ID de paciente inválido" });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [paciente] = await connection.query(`
      SELECT id_paciente, nombre, id_mirror
      FROM pacientes
      WHERE id_paciente = ?
      FOR UPDATE
    `, [idPaciente]);

    if (paciente.length === 0) {
      await connection.rollback();
      connection.release();
      connection = null;

      return res.status(404).json({ message: "Paciente no encontrado" });
    }

    const [sesionesActivas] = await connection.query(`
      SELECT
        id_sesion,
        id_paciente,
        modalidad,
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
    `, [idPaciente]);

    let idSesion;
    let sesionExistente = false;
    let linkActual = null;

    if (sesionesActivas.length > 0) {
      idSesion = Number(sesionesActivas[0].id_sesion);
      sesionExistente = true;
      linkActual = sesionesActivas[0].link_videollamada;

      await connection.query(`
        UPDATE sesiones
        SET modalidad = 'videollamada'
        WHERE id_sesion = ?
      `, [idSesion]);

      console.log("♻️ Reutilizando sesión activa para videollamada:", {
        idSesion,
        idPaciente
      });

    } else {
      const [result] = await connection.query(`
        INSERT INTO sesiones
          (id_cita, id_paciente, modalidad, notas, link_videollamada, estado)
        VALUES (?, ?, ?, ?, ?, ?)
      `, [
        null,
        idPaciente,
        "videollamada",
        "Sesión iniciada desde videollamada",
        null,
        "activa"
      ]);

      idSesion = Number(result.insertId);
      sesionExistente = false;
      linkActual = null;

      console.log("🆕 Nueva sesión de videollamada creada:", {
        idSesion,
        idPaciente
      });
    }

    const [numero] = await connection.query(`
      SELECT COUNT(*) AS numero_sesion
      FROM sesiones
      WHERE id_paciente = ?
        AND id_sesion <= ?
    `, [idPaciente, idSesion]);

    const numeroSesion = Number(numero[0]?.numero_sesion || 1);

    const frontendOrigin =
      process.env.FRONTEND_URL || `http://${req.hostname}:5175`;

    let sala = null;
    let linkPsicologo = null;

    if (linkActual) {
      const partesLink = linkActual.split("/").filter(Boolean);
      const salaExistente = partesLink[partesLink.length - 1];
      const partesSala = salaExistente ? salaExistente.split("-") : [];

      const salaValida =
        partesSala.length >= 4 &&
        partesSala[0] === "sala" &&
        Number(partesSala[1]) === idSesion &&
        Number(partesSala[2]) === idPaciente;

      if (salaValida) {
        sala = salaExistente;
        linkPsicologo = `${frontendOrigin}/SalaVideollamada/${sala}`;

        console.log("♻️ Reutilizando sala válida:", {
          idSesion,
          idPaciente,
          sala
        });
      }
    }

    if (!sala) {
      sala = `sala-${idSesion}-${idPaciente}-${Date.now()}`;
      linkPsicologo = `${frontendOrigin}/SalaVideollamada/${sala}`;

      await connection.query(`
        UPDATE sesiones
        SET
          modalidad = 'videollamada',
          link_videollamada = ?
        WHERE id_sesion = ?
      `, [linkPsicologo, idSesion]);

      console.log("📹 Sala nueva creada:", {
        idSesion,
        idPaciente,
        sala
      });
    }

    const linkPaciente =
      `${frontendOrigin}/videollamada-paciente/${sala}`;

    await connection.commit();
    connection.release();
    connection = null;

    return res.json({
      success: true,
      existente: sesionExistente,
      id_sesion: idSesion,
      id_paciente: idPaciente,
      numero_sesion: numeroSesion,
      modalidad: "videollamada",
      sala,
      link: linkPsicologo,
      link_psicologo: linkPsicologo,
      link_paciente: linkPaciente,
      paciente: {
        id_paciente: paciente[0].id_paciente,
        nombre: paciente[0].nombre,
        id_mirror: paciente[0].id_mirror
      },
      message: sesionExistente
        ? "✅ Sesión activa recuperada para videollamada"
        : "✅ Sesión de videollamada creada correctamente"
    });

  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("❌ Error haciendo rollback:", rollbackError);
      }
    }

    console.error("❌ Error al iniciar videollamada:", err);
    return res.status(500).json({
      message: "Error al iniciar videollamada"
    });

  } finally {
    if (connection) connection.release();
  }
}

/* ==================================================
   FINALIZAR SESIÓN
================================================== */
export async function finalizarSesion(req, res) {
  const { id } = req.params;

  try {
    if (!id) {
      return res.status(400).json({ message: "Falta el ID de la sesión" });
    }

    const idSesion = Number(id);
    if (!Number.isInteger(idSesion)) {
      return res.status(400).json({ message: "ID de sesión inválido" });
    }

    const [sesion] = await pool.query(`
      SELECT id_sesion, id_paciente, modalidad, estado
      FROM sesiones
      WHERE id_sesion = ?
    `, [idSesion]);

    if (!sesion.length) {
      return res.status(404).json({ message: "⚠️ Sesión no encontrada" });
    }

    if (sesion[0].estado === "finalizada") {
      return res.status(400).json({
        message: "⚠️ Esta sesión ya está finalizada"
      });
    }

    const [result] = await pool.query(`
      UPDATE sesiones
      SET
        estado = 'finalizada',
        fecha_fin = NOW()
      WHERE id_sesion = ?
    `, [idSesion]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "⚠️ Sesión no encontrada" });
    }

    const idPaciente = Number(sesion[0].id_paciente);

    console.log("🛑 Sesión finalizada:", {
      idSesion,
      idPaciente,
      modalidad: sesion[0].modalidad
    });

    return res.json({
      success: true,
      id_sesion: idSesion,
      id_paciente: idPaciente,
      modalidad: sesion[0].modalidad,
      estado: "finalizada",
      message: "✅ Sesión finalizada correctamente"
    });

  } catch (err) {
    console.error("❌ Error al finalizar sesión:", err);
    return res.status(500).json({ message: "Error al finalizar sesión" });
  }
}

/* ==================================================
   GENERAR LINK DE VIDEOLLAMADA
   SOBRE UNA SESIÓN YA EXISTENTE
================================================== */
export async function generarLinkVideollamada(req, res) {
  const { id } = req.params;

  try {
    if (!id) {
      return res.status(400).json({ message: "Falta el ID de la sesión" });
    }

    const idSesion = Number(id);
    if (!Number.isInteger(idSesion)) {
      return res.status(400).json({ message: "ID de sesión inválido" });
    }

    const [sesion] = await pool.query(`
      SELECT
        id_sesion,
        id_paciente,
        modalidad,
        estado,
        link_videollamada
      FROM sesiones
      WHERE id_sesion = ?
    `, [idSesion]);

    if (!sesion.length) {
      return res.status(404).json({ message: "⚠️ Sesión no encontrada" });
    }

    const idPaciente = Number(sesion[0].id_paciente);

    if (sesion[0].estado === "finalizada") {
      return res.status(400).json({
        message: "⚠️ Esta sesión ya está finalizada"
      });
    }

    if (sesion[0].modalidad !== "videollamada") {
      await pool.query(`
        UPDATE sesiones
        SET modalidad = 'videollamada'
        WHERE id_sesion = ?
      `, [idSesion]);
    }

    const [numero] = await pool.query(`
      SELECT COUNT(*) AS numero_sesion
      FROM sesiones
      WHERE id_paciente = ?
        AND id_sesion <= ?
    `, [idPaciente, idSesion]);

    const numeroSesion = Number(numero[0]?.numero_sesion || 1);

    const frontendOrigin =
      process.env.FRONTEND_URL || `http://${req.hostname}:5175`;

    /* ==================================================
       REUTILIZAR SALA EXISTENTE
    ================================================== */
    if (sesion[0].link_videollamada) {
      const linkPsicologo = sesion[0].link_videollamada;
      const partesLink = linkPsicologo.split("/").filter(Boolean);
      const sala = partesLink[partesLink.length - 1];
      const partesSala = sala ? sala.split("-") : [];

      const salaValida =
        partesSala.length >= 4 &&
        partesSala[0] === "sala" &&
        Number(partesSala[1]) === idSesion &&
        Number(partesSala[2]) === idPaciente;

      if (salaValida) {
        const linkPaciente =
          `${frontendOrigin}/videollamada-paciente/${sala}`;

        console.log("♻️ Sala existente recuperada:", {
          idSesion,
          idPaciente,
          sala
        });

        return res.json({
          success: true,
          existente: true,
          id_sesion: idSesion,
          id_paciente: idPaciente,
          numero_sesion: numeroSesion,
          modalidad: "videollamada",
          sala,
          link: linkPsicologo,
          link_psicologo: linkPsicologo,
          link_paciente: linkPaciente,
          message: "✅ La sala existente fue recuperada"
        });
      }
    }

    /* ==================================================
       CREAR NUEVA SALA
    ================================================== */
    const sala = `sala-${idSesion}-${idPaciente}-${Date.now()}`;
    const linkPsicologo =
      `${frontendOrigin}/SalaVideollamada/${sala}`;
    const linkPaciente =
      `${frontendOrigin}/videollamada-paciente/${sala}`;

    await pool.query(`
      UPDATE sesiones
      SET
        modalidad = 'videollamada',
        link_videollamada = ?
      WHERE id_sesion = ?
    `, [linkPsicologo, idSesion]);

    console.log("📹 Link de videollamada generado:", {
      idSesion,
      idPaciente,
      sala
    });

    return res.json({
      success: true,
      existente: false,
      id_sesion: idSesion,
      id_paciente: idPaciente,
      numero_sesion: numeroSesion,
      modalidad: "videollamada",
      sala,
      link: linkPsicologo,
      link_psicologo: linkPsicologo,
      link_paciente: linkPaciente,
      message: "✅ Link generado correctamente"
    });

  } catch (err) {
    console.error("❌ Error al generar link de videollamada:", err);
    return res.status(500).json({
      message: "Error al generar link de videollamada"
    });
  }
}