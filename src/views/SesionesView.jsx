// src/views/SesionesView.jsx
import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";
import VideoRecorder from "../components/VideoRecorder";

export default function SesionesView() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();

  const [sesiones, setSesiones] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sesionAbierta, setSesionAbierta] = useState(null);
  const [archivosSesion, setArchivosSesion] = useState({});
  const [cargandoArchivos, setCargandoArchivos] = useState(false);
  const [sesionesVisibles, setSesionesVisibles] = useState(5);
  const [mostrarNuevaSesion, setMostrarNuevaSesion] = useState(false);
  const [modalidadNueva, setModalidadNueva] = useState("presencial");
  const [creandoSesion, setCreandoSesion] = useState(false);
  const [mensajeSesion, setMensajeSesion] = useState("");
  const [notasIA, setNotasIA] = useState({});
  const [cargandoNotaIA, setCargandoNotaIA] = useState({});
  const [guardandoNotaIA, setGuardandoNotaIA] = useState({});
  const [mensajeNotaIA, setMensajeNotaIA] = useState({});
  const [transcribiendoAudio, setTranscribiendoAudio] = useState({});
  const [mensajeTranscripcion, setMensajeTranscripcion] = useState({});
  const [reintentandoTranscripcion, setReintentandoTranscripcion] = useState({});

  // =====================================================
  // CARGAR SESIONES
  // =====================================================
  const fetchSesiones = async () => {
    try {
      setLoading(true);
      setError("");

      const token = getToken();
      const res = await fetch(
        `https://reflejoyalma.com/api/sesiones/paciente/${idPaciente}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const data = await res.json();

      if (!res.ok) {
        throw new Error(
          data.message || "No se pudieron obtener las sesiones"
        );
      }

      setSesiones(Array.isArray(data) ? data : data.sesiones || []);
    } catch (err) {
      console.error("❌ Error al obtener sesiones:", err);
      setError(
        err.message ||
          "No fue posible cargar las sesiones del paciente."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (idPaciente) fetchSesiones();
  }, [idPaciente]);

  // =====================================================
  // SESIÓN ACTIVA
  // =====================================================
  const sesionActiva =
    sesiones.find((s) => s.estado === "activa") || null;

  const abrirSesionActiva = async () => {
    if (!sesionActiva) return;

    setMostrarNuevaSesion(false);
    setMensajeSesion("");
    setSesionAbierta(sesionActiva.id_sesion);

    if (!Object.prototype.hasOwnProperty.call(notasIA, sesionActiva.id_sesion)) {
      await cargarNotaIA(sesionActiva.id_sesion);
    }

    if (
      Object.prototype.hasOwnProperty.call(
        archivosSesion,
        sesionActiva.id_sesion
      )
    ) {
      return;
    }

    await cargarArchivosSesion(sesionActiva.id_sesion);
  };

  // =====================================================
  // CREAR NUEVA SESIÓN
  // =====================================================
  const crearNuevaSesion = async () => {
    if (creandoSesion) return;

    if (sesionActiva) {
      setMostrarNuevaSesion(false);
      setError(
        `⚠️ Ya existe una sesión activa (#${sesionActiva.id_sesion}). Termina esa consulta antes de crear una nueva.`
      );
      setSesionAbierta(sesionActiva.id_sesion);
      return;
    }

    try {
      setCreandoSesion(true);
      setError("");
      setMensajeSesion("");

      const token = getToken();

      const res = await fetch(
        "https://reflejoyalma.com/api/sesiones",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            id_paciente: Number(idPaciente),
            modalidad: modalidadNueva,
          }),
        }
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        if (res.status === 409 && data.id_sesion_activa) {
          setMostrarNuevaSesion(false);
          setSesionAbierta(Number(data.id_sesion_activa));
          await fetchSesiones();
        }

        throw new Error(
          data.message || "No se pudo crear la sesión."
        );
      }

      setMensajeSesion(
        `✅ Sesión ${data.numero_sesion} creada correctamente`
      );

      setMostrarNuevaSesion(false);

      await fetchSesiones();

      if (modalidadNueva === "presencial") {
        setSesionAbierta(data.id_sesion);
        return;
      }

      const resVideo = await fetch(
        `https://reflejoyalma.com/api/sesiones/${data.id_sesion}/videollamada`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const dataVideo = await resVideo.json().catch(() => ({}));

      if (!resVideo.ok) {
        throw new Error(
          dataVideo.message ||
            "La sesión fue creada, pero no se pudo generar la videollamada."
        );
      }

      if (dataVideo.sala) {
        navigate(`/SalaVideollamada/${dataVideo.sala}`);
      }
    } catch (err) {
      console.error("❌ Error creando sesión:", err);
      setError(
        err.message || "No fue posible crear la sesión."
      );
    } finally {
      setCreandoSesion(false);
    }
  };

  // =====================================================
  // CARGAR MULTIMEDIA
  // =====================================================
  const cargarArchivosSesion = async (idSesion) => {
    try {
      setCargandoArchivos(true);

      const token = getToken();

      const res = await fetch(
        `https://reflejoyalma.com/api/archivos/sesion/${idSesion}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!res.ok) {
        throw new Error(
          "No se pudieron obtener las grabaciones de la sesión."
        );
      }

      const data = await res.json();

      console.log(
        "🎥 Archivos multimedia recibidos:",
        data
      );

      const lista = Array.isArray(data) ? data : [];

      setArchivosSesion((previous) => ({
        ...previous,
        [idSesion]: lista,
      }));

      return lista;
    } catch (err) {
      console.error(
        "❌ Error al obtener archivos de la sesión:",
        err
      );

      setArchivosSesion((previous) => ({
        ...previous,
        [idSesion]: [],
      }));

      return [];
    } finally {
      setCargandoArchivos(false);
    }
  };

  // =====================================================
  // TRANSCRIPCIÓN AUTOMÁTICA DE AUDIO
  // =====================================================
  const transcribirAudioAutomaticamente = async (idSesion, archivoGuardado = {}) => {
    if (!idSesion) return;

    try {
      setTranscribiendoAudio((prev) => ({ ...prev, [idSesion]: true }));
      setMensajeTranscripcion((prev) => ({
        ...prev,
        [idSesion]: "⏳ Audio guardado. Iniciando transcripción...",
      }));

      let idVideo = Number(
        archivoGuardado?.id_video ||
        archivoGuardado?.id ||
        0
      );

      if (!idVideo) {
        const lista = await cargarArchivosSesion(idSesion);

        const audioPendiente = [...lista]
          .filter((item) => {
            const esAudio =
              item.tipo === "audio" ||
              String(item.formato || "").startsWith("audio/");

            return (
              esAudio &&
              item.transcripcion_estado !== "completada"
            );
          })
          .sort(
            (a, b) =>
              Number(b.id_video || 0) -
              Number(a.id_video || 0)
          )[0];

        idVideo = Number(audioPendiente?.id_video || 0);
      }

      if (!idVideo) {
        throw new Error(
          "El audio se guardó, pero no se encontró su identificador para transcribirlo."
        );
      }

      const token = getToken();
      const API_URL = `https://reflejoyalma.com`;

      setMensajeTranscripcion((prev) => ({
        ...prev,
        [idSesion]: "🎙️ Transcribiendo audio con IA...",
      }));

      console.log(
        `🎙️ Iniciando transcripción automática del archivo #${idVideo}`
      );

      const res = await fetch(
        `${API_URL}/api/archivos/${idVideo}/transcribir`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(
          data.message ||
          data.error ||
          "No se pudo transcribir el audio."
        );
      }

      console.log(
        "✅ Transcripción automática completada:",
        data
      );

      setMensajeTranscripcion((prev) => ({
        ...prev,
        [idSesion]: "✅ Audio transcrito correctamente",
      }));

      await cargarArchivosSesion(idSesion);
    } catch (err) {
      console.error(
        "❌ Error en transcripción automática:",
        err
      );

      setMensajeTranscripcion((prev) => ({
        ...prev,
        [idSesion]:
          `⚠️ El audio se guardó, pero la transcripción falló: ${
            err.message || "Error desconocido"
          }`,
      }));

      await cargarArchivosSesion(idSesion);
    } finally {
      setTranscribiendoAudio((prev) => ({
        ...prev,
        [idSesion]: false,
      }));
    }
  };

  // =====================================================
  // REINTENTAR TRANSCRIPCIÓN DE AUDIO O VIDEO
  // =====================================================
  const reintentarTranscripcion = async (idVideo, idSesion) => {
    if (!idVideo || !idSesion || reintentandoTranscripcion[idVideo]) return;

    try {
      setReintentandoTranscripcion((prev) => ({
        ...prev,
        [idVideo]: true,
      }));

      setArchivosSesion((prev) => ({
        ...prev,
        [idSesion]: (prev[idSesion] || []).map((archivo) =>
          Number(archivo.id_video) === Number(idVideo)
            ? { ...archivo, transcripcion_estado: "procesando" }
            : archivo
        ),
      }));

      const token = getToken();
      const API_URL = `https://reflejoyalma.com`;

      console.log(`🔄 Reintentando transcripción del archivo #${idVideo}`);

      const res = await fetch(
        `${API_URL}/api/archivos/${idVideo}/transcribir`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(
          data.message ||
          data.error ||
          "No se pudo reintentar la transcripción."
        );
      }

      console.log("✅ Reintento de transcripción completado:", data);
      await cargarArchivosSesion(idSesion);

    } catch (err) {
      console.error("❌ Error reintentando transcripción:", err);
      await cargarArchivosSesion(idSesion);

    } finally {
      setReintentandoTranscripcion((prev) => ({
        ...prev,
        [idVideo]: false,
      }));
    }
  };

  // =====================================================
  // NOTAS DE LA SESIÓN PARA IA
  // =====================================================
  const cargarNotaIA = async (idSesion) => {
    if (Object.prototype.hasOwnProperty.call(notasIA, idSesion)) return;
    try {
      setCargandoNotaIA((prev) => ({ ...prev, [idSesion]: true }));
      const token = getToken();
      const API_URL = `https://reflejoyalma.com`;
      const res = await fetch(`${API_URL}/api/notas/ia/${idSesion}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error(data?.message || "No se pudo cargar la nota para IA.");
      setNotasIA((prev) => ({ ...prev, [idSesion]: data?.nota || "" }));
    } catch (err) {
      console.error("❌ Error cargando nota IA:", err);
      setMensajeNotaIA((prev) => ({ ...prev, [idSesion]: "⚠️ No se pudo cargar la nota guardada." }));
    } finally {
      setCargandoNotaIA((prev) => ({ ...prev, [idSesion]: false }));
    }
  };

  const guardarNotaIA = async (idSesion) => {
    const nota = String(notasIA[idSesion] || "").trim();
    if (!nota) {
      setMensajeNotaIA((prev) => ({ ...prev, [idSesion]: "⚠️ Escribe una nota antes de guardarla." }));
      return;
    }
    try {
      setGuardandoNotaIA((prev) => ({ ...prev, [idSesion]: true }));
      setMensajeNotaIA((prev) => ({ ...prev, [idSesion]: "" }));
      const token = getToken();
      const API_URL = `https://reflejoyalma.com`;
      const res = await fetch(`${API_URL}/api/notas/ia`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ id_sesion: idSesion, nota }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || "No se pudo guardar la nota para IA.");
      setNotasIA((prev) => ({ ...prev, [idSesion]: nota }));
      setMensajeNotaIA((prev) => ({ ...prev, [idSesion]: data.message || "✅ Nota para IA guardada" }));
    } catch (err) {
      console.error("❌ Error guardando nota IA:", err);
      setMensajeNotaIA((prev) => ({ ...prev, [idSesion]: `⚠️ ${err.message || "No se pudo guardar la nota."}` }));
    } finally {
      setGuardandoNotaIA((prev) => ({ ...prev, [idSesion]: false }));
    }
  };

  // =====================================================
  // ABRIR / CERRAR SESIÓN
  // =====================================================
  const toggleSesion = async (idSesion) => {
    if (sesionAbierta === idSesion) {
      setSesionAbierta(null);
      return;
    }

    setSesionAbierta(idSesion);

    const sesion = sesiones.find((item) => item.id_sesion === idSesion);
    if (sesion?.estado === "activa" && !Object.prototype.hasOwnProperty.call(notasIA, idSesion)) {
      await cargarNotaIA(idSesion);
    }

    if (
      Object.prototype.hasOwnProperty.call(
        archivosSesion,
        idSesion
      )
    ) {
      return;
    }

    await cargarArchivosSesion(idSesion);
  };

  // =====================================================
// TERMINAR CONSULTA
//
// IMPORTANTE:
// NO finaliza todavía la sesión en BD.
// Primero abre el Preanálisis IA de esta sesión.
// =====================================================
const terminarConsulta = (sesion) => {
  if (!sesion || sesion.estado !== "activa") return;

  setError("");
  setMensajeSesion("");

  console.log("🏁 Iniciando Preanálisis IA:", {
    id_sesion: sesion.id_sesion,
    id_paciente: Number(idPaciente),
  });

  navigate(
    `/paciente/${idPaciente}/sesion/${sesion.id_sesion}/preanalisis`
  );
};

  // =====================================================
  // PRUEBAS PSICOLÓGICAS DE LA SESIÓN
  // =====================================================
  const gestionarPruebasSesion = (sesion) => {
    if (!sesion || sesion.estado !== "activa") return;

    setError("");
    setMensajeSesion("");

    navigate(
      `/paciente/${idPaciente}/sesion/${sesion.id_sesion}/pruebas`
    );
  };

  // =====================================================
  // PAGINACIÓN
  // =====================================================
  const mostrarMasSesiones = () => {
    setSesionesVisibles((actual) =>
      Math.min(actual + 5, sesiones.length)
    );
  };

  const mostrarMenosSesiones = () => {
    setSesionesVisibles(5);
    setSesionAbierta(null);

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const volverAlExpediente = () => {
    navigate(`/paciente/${idPaciente}`);
  };

  // =====================================================
  // CARGANDO
  // =====================================================
  if (loading) {
    return (
      <div style={loadingPage}>
        <div style={loadingCard}>
          <div style={loadingIcon}>⏳</div>

          <h3 style={loadingTitle}>
            Cargando sesiones...
          </h3>

          <p style={loadingText}>
            Estamos obteniendo el historial de sesiones
            del paciente.
          </p>
        </div>
      </div>
    );
  }

  const sesionesMostradas =
    sesiones.slice(0, sesionesVisibles);

  const hayMasSesiones =
    sesionesVisibles < sesiones.length;

  const mostrandoTodas =
    sesionesVisibles >= sesiones.length &&
    sesiones.length > 5;

  return (
    <div style={page}>
      <div style={container}>
        {/* =================================================
            ENCABEZADO
        ================================================= */}
        <div style={header}>
          <div>
            <div style={smallLabel}>
              EXPEDIENTE DEL PACIENTE
            </div>

            <h1 style={title}>
              📅 Historial de Sesiones
            </h1>

            <p style={subtitle}>
              Consulta las sesiones clínicas registradas
              para este paciente.
            </p>
          </div>

          <div style={sessionCounter}>
            <span style={counterNumber}>
              {sesiones.length}
            </span>

            <span style={counterLabel}>
              {sesiones.length === 1
                ? "sesión"
                : "sesiones"}
            </span>
          </div>
        </div>

        {/* =================================================
            SESIÓN ACTIVA
        ================================================= */}
        {sesionActiva && (
          <div style={activeSessionBox}>
            <div style={activeSessionInfo}>
              <div style={activeSessionTitle}>
                🟢 Sesión activa en curso
              </div>

              <div style={activeSessionText}>
                Este paciente tiene la sesión #
                {sesionActiva.numero_sesion ||
                  sesionActiva.id_sesion}{" "}
                abierta. Debes terminarla antes de iniciar
                otra consulta.
              </div>
            </div>

            <button
              type="button"
              onClick={abrirSesionActiva}
              style={activeSessionButton}
            >
              Ver sesión activa
            </button>
          </div>
        )}

        {/* =================================================
            NUEVA SESIÓN
        ================================================= */}
        <div style={newSessionSection}>
          <button
            type="button"
            disabled={Boolean(sesionActiva)}
            onClick={() => {
              if (sesionActiva) return;

              setMostrarNuevaSesion(
                !mostrarNuevaSesion
              );

              setMensajeSesion("");
              setError("");
            }}
            style={{
              ...newSessionButton,
              ...(sesionActiva
                ? disabledNewSessionButton
                : {}),
            }}
          >
            {sesionActiva
              ? "🔒 Hay una sesión activa"
              : "➕ Nueva sesión"}
          </button>

          {sesionActiva && (
            <div style={activeHint}>
              Finaliza la consulta activa antes de crear
              una nueva sesión.
            </div>
          )}

          {mostrarNuevaSesion &&
            !sesionActiva && (
              <div style={newSessionCard}>
                <h3 style={newSessionTitle}>
                  Nueva sesión clínica
                </h3>

                <p style={newSessionText}>
                  Selecciona cómo se realizará esta sesión.
                </p>

                <div style={modalityGrid}>
                  <button
                    type="button"
                    onClick={() =>
                      setModalidadNueva("presencial")
                    }
                    style={{
                      ...modalityCard,
                      ...(modalidadNueva ===
                      "presencial"
                        ? modalityCardSelected
                        : {}),
                    }}
                  >
                    <div style={modalityIcon}>
                      🏥
                    </div>

                    <div>
                      <div style={modalityTitle}>
                        Presencial
                      </div>

                      <div style={modalityText}>
                        Consulta realizada presencialmente.
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      setModalidadNueva(
                        "videollamada"
                      )
                    }
                    style={{
                      ...modalityCard,
                      ...(modalidadNueva ===
                      "videollamada"
                        ? modalityCardSelected
                        : {}),
                    }}
                  >
                    <div style={modalityIcon}>
                      🎥
                    </div>

                    <div>
                      <div style={modalityTitle}>
                        Videollamada
                      </div>

                      <div style={modalityText}>
                        Consulta remota con sala de
                        videollamada.
                      </div>
                    </div>
                  </button>
                </div>

                <div style={newSessionActions}>
                  <button
                    type="button"
                    disabled={creandoSesion}
                    onClick={() =>
                      setMostrarNuevaSesion(false)
                    }
                    style={cancelSessionButton}
                  >
                    Cancelar
                  </button>

                  <button
                    type="button"
                    disabled={creandoSesion}
                    onClick={crearNuevaSesion}
                    style={{
                      ...startSessionButton,
                      ...(creandoSesion
                        ? disabledButton
                        : {}),
                    }}
                  >
                    {creandoSesion
                      ? "Creando..."
                      : modalidadNueva ===
                        "videollamada"
                      ? "🎥 Iniciar videollamada"
                      : "🏥 Iniciar sesión presencial"}
                  </button>
                </div>
              </div>
            )}

          {mensajeSesion && (
            <div style={successBox}>
              {mensajeSesion}
            </div>
          )}
        </div>

        {/* =================================================
            ERROR
        ================================================= */}
        {error && (
          <div style={errorBox}>
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {/* =================================================
            SIN SESIONES
        ================================================= */}
        {!error && sesiones.length === 0 && (
          <div style={emptyBox}>
            <div style={emptyIcon}>📅</div>

            <h3 style={emptyTitle}>
              No hay sesiones registradas
            </h3>

            <p style={emptyText}>
              Todavía no se han registrado sesiones
              clínicas para este paciente.
            </p>
          </div>
        )}

        {/* =================================================
            LISTA DE SESIONES
        ================================================= */}
        {!error && sesiones.length > 0 && (
          <>
            <div style={sessionsList}>
              {sesionesMostradas.map(
                (s, index) => {
                  const fecha = s.fecha
                    ? new Date(s.fecha)
                    : null;

                  const abierta =
                    sesionAbierta === s.id_sesion;

                  const archivos =
                    archivosSesion[s.id_sesion] ||
                    [];

                  const activa =
                    s.estado === "activa";

                  return (
                    <div
                      key={s.id_sesion}
                      style={{
                        ...sessionCard,
                        ...(abierta
                          ? sessionCardOpen
                          : {}),
                        ...(activa
                          ? activeSessionCard
                          : {}),
                      }}
                    >
                      {/* CABECERA */}
                      <button
                        type="button"
                        onClick={() =>
                          toggleSesion(
                            s.id_sesion
                          )
                        }
                        style={sessionHeaderButton}
                      >
                        <div style={sessionNumber}>
                          {s.numero_sesion ||
                            sesiones.length -
                              index}
                        </div>

                        <div style={sessionMainInfo}>
                          <div style={sessionLabel}>
                            SESIÓN CLÍNICA
                          </div>

                          <h3 style={sessionTitle}>
                            Sesión #
                            {s.numero_sesion ||
                              sesiones.length -
                                index}
                          </h3>

                          <div
                            style={modalityBadge}
                          >
                            {s.modalidad ===
                            "videollamada"
                              ? "🎥 Videollamada"
                              : "🏥 Presencial"}
                          </div>

                          {activa && (
                            <span
                              style={
                                activeBadge
                              }
                            >
                              🟢 ACTIVA
                            </span>
                          )}

                          <div style={sessionDate}>
                            📅{" "}
                            {fecha
                              ? fecha.toLocaleDateString(
                                  "es-MX",
                                  {
                                    day: "2-digit",
                                    month: "long",
                                    year: "numeric",
                                  }
                                )
                              : "Fecha no disponible"}
                          </div>
                        </div>

                        <div
                          style={{
                            ...expandButton,
                            ...(abierta
                              ? expandButtonOpen
                              : {}),
                          }}
                        >
                          <span>
                            {abierta
                              ? "Ocultar"
                              : "Ver detalles"}
                          </span>

                          <span style={arrow}>
                            {abierta
                              ? "▲"
                              : "▼"}
                          </span>
                        </div>
                      </button>

                      {/* DETALLES */}
                      {abierta && (
                        <div style={details}>
                          {fecha && (
                            <div style={detailItem}>
                              <div style={detailIcon}>
                                🕐
                              </div>

                              <div>
                                <div
                                  style={
                                    detailLabel
                                  }
                                >
                                  Hora de la sesión
                                </div>

                                <div
                                  style={
                                    detailValue
                                  }
                                >
                                  {fecha.toLocaleTimeString(
                                    "es-MX",
                                    {
                                      hour: "2-digit",
                                      minute:
                                        "2-digit",
                                    }
                                  )}
                                </div>
                              </div>
                            </div>
                          )}

                          <div style={detailItem}>
                            <div style={detailIcon}>
                              🆔
                            </div>

                            <div>
                              <div
                                style={
                                  detailLabel
                                }
                              >
                                Identificador de
                                sesión
                              </div>

                              <div
                                style={
                                  detailValue
                                }
                              >
                                #{s.id_sesion}
                              </div>
                            </div>
                          </div>

                          <div style={detailItem}>
                            <div style={detailIcon}>
                              {s.estado ===
                              "finalizada"
                                ? "✅"
                                : "🟢"}
                            </div>

                            <div>
                              <div
                                style={
                                  detailLabel
                                }
                              >
                                Estado
                              </div>

                              <div
                                style={
                                  detailValue
                                }
                              >
                                {s.estado ===
                                "finalizada"
                                  ? "Finalizada"
                                  : "Activa"}
                              </div>
                            </div>
                          </div>

                          <div style={detailItem}>
                            <div style={detailIcon}>
                              {s.modalidad ===
                              "videollamada"
                                ? "🎥"
                                : "🏥"}
                            </div>

                            <div>
                              <div
                                style={
                                  detailLabel
                                }
                              >
                                Modalidad
                              </div>

                              <div
                                style={
                                  detailValue
                                }
                              >
                                {s.modalidad ===
                                "videollamada"
                                  ? "Videollamada"
                                  : "Presencial"}
                              </div>
                            </div>
                          </div>

                          {/* NOTAS */}
                          <div style={notesBox}>
                            <div style={notesTitle}>
                              📝 Notas de la sesión
                            </div>

                            <p style={notesText}>
                              {s.notas
                                ? s.notas
                                : "Sin notas registradas."}
                            </p>
                          </div>

                          {/* NOTAS PARA PREANÁLISIS IA - SESIÓN ACTIVA */}
                          {activa && (
                            <div style={aiNotesBox}>
                              <div style={aiNotesHeader}>
                                <div>
                                  <div style={aiNotesTitle}>📝 Notas de la sesión para IA</div>
                                  <div style={aiNotesText}>
                                    Agrega observaciones o información relevante de esta consulta. Es opcional y se tomará en cuenta al generar el Preanálisis IA.
                                  </div>
                                </div>
                                <span style={aiNotesOptional}>Opcional</span>
                              </div>

                              {cargandoNotaIA[s.id_sesion] ? (
                                <div style={aiNotesLoading}>⏳ Cargando nota...</div>
                              ) : (
                                <>
                                  <textarea
                                    value={notasIA[s.id_sesion] || ""}
                                    onChange={(e) => {
                                      const value = e.target.value;
                                      setNotasIA((prev) => ({ ...prev, [s.id_sesion]: value }));
                                      setMensajeNotaIA((prev) => ({ ...prev, [s.id_sesion]: "" }));
                                    }}
                                    placeholder="Ejemplo: La paciente se mostró inquieta al hablar de su trabajo, aunque verbalmente dijo sentirse tranquila..."
                                    rows={6}
                                    style={aiNotesTextarea}
                                  />
                                  <div style={aiNotesActions}>
                                    <span style={aiNotesStatus}>
                                      {mensajeNotaIA[s.id_sesion] || "Puedes guardar y volver a editar mientras la sesión siga activa."}
                                    </span>
                                    <button
                                      type="button"
                                      onClick={() => guardarNotaIA(s.id_sesion)}
                                      disabled={Boolean(guardandoNotaIA[s.id_sesion])}
                                      style={{ ...aiNotesButton, ...(guardandoNotaIA[s.id_sesion] ? disabledButton : {}) }}
                                    >
                                      {guardandoNotaIA[s.id_sesion] ? "Guardando..." : "💾 Guardar notas"}
                                    </button>
                                  </div>
                                </>
                              )}
                            </div>
                          )}

                          {/* GRABACIÓN DE AUDIO - SOLO PRESENCIAL ACTIVA */}
                          {activa && s.modalidad === "presencial" && (
                            <div style={audioRecorderBox}>
                              <div style={audioRecorderInfo}>
                                <div style={audioRecorderTitle}>
                                  🎙️ Grabar audio de la sesión
                                </div>
                                <div style={audioRecorderText}>
                                  Grabación opcional de la consulta presencial. Se guardará ligada a esta sesión.
                                </div>
                              </div>
                              <VideoRecorder
                                idSesion={s.id_sesion}
                                tipo="audio"
                                onSaved={async (data) => {
                                  await transcribirAudioAutomaticamente(
                                    s.id_sesion,
                                    data
                                  );
                                }}
                              />

                              {mensajeTranscripcion[s.id_sesion] && (
                                <div
                                  style={{
                                    marginTop: "10px",
                                    fontSize: "11px",
                                    lineHeight: "1.5",
                                    color: transcribiendoAudio[s.id_sesion]
                                      ? "#3155A4"
                                      : mensajeTranscripcion[s.id_sesion].startsWith("✅")
                                      ? "#2F855A"
                                      : "#B7791F",
                                  }}
                                >
                                  {mensajeTranscripcion[s.id_sesion]}
                                </div>
                              )}
                            </div>
                          )}

                          {/* PRUEBAS PSICOLÓGICAS DE LA SESIÓN */}
                          {activa && (
                            <div style={sessionTestsBox}>
                              <div style={sessionTestsInfo}>
                                <div style={sessionTestsTitle}>
                                  🧪 Pruebas psicológicas
                                </div>
                                <div style={sessionTestsText}>
                                  Habilita y administra pruebas vinculadas específicamente a esta sesión clínica.
                                </div>
                              </div>

                              <button
                                type="button"
                                onClick={() => gestionarPruebasSesion(s)}
                                style={sessionTestsButton}
                              >
                                🧪 Gestionar pruebas
                              </button>
                            </div>
                          )}

                          {/* TERMINAR CONSULTA */}
                          {activa && (
                            <div
                              style={
                                finishConsultationBox
                              }
                            >
                              <div
                                style={
                                  finishConsultationInfo
                                }
                              >
                                <div
                                  style={
                                    finishConsultationTitle
                                  }
                                >
                                  🏁 Cierre de
                                  consulta
                                </div>

                                <div
                                  style={
                                    finishConsultationText
                                  }
                                >
                                  Cuando termine la
                                  consulta,
                                  continuaremos con
                                  el Preanálisis IA
                                  antes de realizar
                                  el cierre clínico.
                                </div>
                              </div>

                              <button
                                type="button"
                                onClick={() =>
                                  terminarConsulta(
                                    s
                                  )
                                }
                                style={
                                  finishConsultationButton
                                }
                              >
                                🏁 Terminar
                                consulta
                              </button>
                            </div>
                          )}

                          {/* MULTIMEDIA */}
                          <div
                            style={multimediaBox}
                          >
                            <div
                              style={
                                multimediaHeader
                              }
                            >
                              <div>
                                <div
                                  style={
                                    multimediaTitle
                                  }
                                >
                                  🎙️🎥 Grabaciones
                                </div>

                                <div
                                  style={
                                    multimediaSubtitle
                                  }
                                >
                                  Audio o video asociado
                                  a la sesión
                                </div>
                              </div>

                              {archivos.length >
                                0 && (
                                <span
                                  style={
                                    multimediaCount
                                  }
                                >
                                  {archivos.length}
                                  {archivos.length === 1
                                    ? " archivo"
                                    : " archivos"}
                                </span>
                              )}
                            </div>

                            {cargandoArchivos &&
                              sesionAbierta ===
                                s.id_sesion && (
                                <div
                                  style={
                                    multimediaLoadingBox
                                  }
                                >
                                  ⏳ Cargando
                                  grabaciones...
                                </div>
                              )}

                            {!cargandoArchivos &&
                              archivos.length ===
                                0 && (
                                <div
                                  style={
                                    multimediaEmptyBox
                                  }
                                >
                                  <span
                                    style={
                                      multimediaEmptyIcon
                                    }
                                  >
                                    🎥
                                  </span>

                                  <span>
                                    No hay grabaciones
                                    asociadas a esta
                                    sesión.
                                  </span>
                                </div>
                              )}

                            {!cargandoArchivos &&
                              archivos.length >
                                0 && (
                                <div
                                  style={
                                    videosList
                                  }
                                >
                                  {archivos.map(
                                    (archivo) => {
                                      const ruta = archivo.ruta_video || "";
                                      const mediaUrl = ruta.startsWith("http")
                                        ? ruta
                                        : `https://reflejoyalma.com${ruta}`;
                                      const esAudio = archivo.tipo === "audio" ||
                                        String(archivo.formato || "").startsWith("audio/");
                                      const estadoTranscripcion =
                                        String(archivo.transcripcion_estado || "pendiente").toLowerCase();
                                      const estaReintentando =
                                        Boolean(reintentandoTranscripcion[archivo.id_video]);

                                      return (
                                        <div key={archivo.id_video} style={videoWrapper}>
                                          <div style={videoHeader}>
                                            <div style={videoHeaderInfo}>
                                              <div style={videoName}>
                                                {esAudio ? "🎙️ Audio de sesión" : "🎬 Grabación de video"}
                                              </div>
                                              <div style={videoDate}>
                                                {archivo.fecha_subida
                                                  ? new Date(archivo.fecha_subida).toLocaleString("es-MX", {
                                                      day: "2-digit", month: "short", year: "numeric",
                                                      hour: "2-digit", minute: "2-digit",
                                                    })
                                                  : "Fecha no disponible"}
                                              </div>
                                            </div>
                                            <span style={videoType}>{esAudio ? "audio" : (archivo.tipo || "video")}</span>
                                          </div>

                                          {esAudio ? (
                                            <audio
                                              key={mediaUrl}
                                              controls
                                              preload="metadata"
                                              src={mediaUrl}
                                              style={audioPlayer}
                                            >
                                              Tu navegador no puede reproducir este audio.
                                            </audio>
                                          ) : (
                                            <div style={videoPlayerContainer}>
                                              <video
                                                key={mediaUrl}
                                                controls
                                                crossOrigin="anonymous"
                                                playsInline
                                                preload="metadata"
                                                src={mediaUrl}
                                                style={videoPlayer}
                                                onError={(e) => {
                                                  console.error("❌ Error reproduciendo video:", e.currentTarget.src);
                                                }}
                                              >
                                                <source src={mediaUrl} type={archivo.formato || "video/webm"} />
                                                Tu navegador no puede reproducir este video.
                                              </video>
                                            </div>
                                          )}

                                          <div style={transcriptionStatusBox}>
                                            <div style={transcriptionStatusRow}>
                                              <span
                                                style={{
                                                  ...transcriptionStatusBadge,
                                                  ...(estadoTranscripcion === "completada"
                                                    ? transcriptionStatusCompleted
                                                    : estadoTranscripcion === "procesando"
                                                    ? transcriptionStatusProcessing
                                                    : estadoTranscripcion === "error"
                                                    ? transcriptionStatusError
                                                    : transcriptionStatusPending),
                                                }}
                                              >
                                                {estadoTranscripcion === "completada"
                                                  ? "🟢 Transcripción completada"
                                                  : estadoTranscripcion === "procesando"
                                                  ? "🔵 Transcribiendo..."
                                                  : estadoTranscripcion === "error"
                                                  ? "🔴 Error al transcribir"
                                                  : "🟡 Transcripción pendiente"}
                                              </span>

                                              {estadoTranscripcion === "error" && (
                                                <button
                                                  type="button"
                                                  disabled={estaReintentando}
                                                  onClick={() =>
                                                    reintentarTranscripcion(
                                                      archivo.id_video,
                                                      s.id_sesion
                                                    )
                                                  }
                                                  style={{
                                                    ...retryTranscriptionButton,
                                                    ...(estaReintentando ? disabledButton : {}),
                                                  }}
                                                >
                                                  {estaReintentando
                                                    ? "⏳ Reintentando..."
                                                    : "🔄 Reintentar transcripción"}
                                                </button>
                                              )}
                                            </div>

                                            {estadoTranscripcion === "completada" &&
                                              archivo.transcripcion && (
                                                <div style={transcriptionReadyText}>
                                                  ✅ La transcripción está lista para el Preanálisis IA.
                                                </div>
                                              )}

                                            {estadoTranscripcion === "procesando" && (
                                              <div style={transcriptionProcessingText}>
                                                Gemini está procesando esta grabación. Puede tardar unos segundos.
                                              </div>
                                            )}

                                            {estadoTranscripcion === "error" && (
                                              <div style={transcriptionErrorText}>
                                                La grabación está guardada. Puedes volver a intentar sin grabarla de nuevo.
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      );
                                    }
                                  )}
                                </div>
                              )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                }
              )}
            </div>

            {/* PAGINACIÓN */}
            {sesiones.length > 5 && (
              <div
                style={paginationContainer}
              >
                {hayMasSesiones && (
                  <button
                    type="button"
                    onClick={
                      mostrarMasSesiones
                    }
                    style={moreButton}
                  >
                    <span
                      style={moreButtonIcon}
                    >
                      ↓
                    </span>

                    <span>
                      Ver 5 sesiones más
                    </span>

                    <span
                      style={remainingText}
                    >
                      (
                      {sesiones.length -
                        sesionesVisibles}{" "}
                      restantes)
                    </span>
                  </button>
                )}

                {mostrandoTodas && (
                  <button
                    type="button"
                    onClick={
                      mostrarMenosSesiones
                    }
                    style={lessButton}
                  >
                    <span>↑</span>
                    <span>Ver menos</span>
                  </button>
                )}
              </div>
            )}
          </>
        )}

        {/* VOLVER */}
        <div style={backContainer}>
          <button
            type="button"
            onClick={volverAlExpediente}
            style={backButton}
          >
            ← Volver al expediente
          </button>
        </div>

        {/* PIE */}
        <div style={footer}>
          <span>🧠 MirrorSoul</span>
          <span>
            Expediente #{idPaciente}
          </span>
        </div>
      </div>
    </div>
  );
}

// =====================================================
// 🎨 ESTILOS
// =====================================================
const page = {
  minHeight: "100vh",
  background:
    "linear-gradient(135deg, #eef6ff 0%, #f8fbff 50%, #e8f3ff 100%)",
  padding: "28px 18px",
  boxSizing: "border-box",
};

const container = {
  width: "100%",
  maxWidth: "1080px",
  margin: "0 auto",
};

const header = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "18px",
  marginBottom: "22px",
};

const smallLabel = {
  fontSize: "10px",
  fontWeight: "800",
  letterSpacing: "1.8px",
  color: "#5C6BC0",
  marginBottom: "5px",
};

const title = {
  margin: 0,
  color: "#173B70",
  fontSize: "28px",
  fontWeight: "800",
};

const subtitle = {
  margin: "6px 0 0",
  color: "#718096",
  fontSize: "13px",
};

const sessionCounter = {
  minWidth: "82px",
  padding: "11px 14px",
  background: "#ffffff",
  borderRadius: "15px",
  boxShadow:
    "0 7px 20px rgba(30,70,120,0.09)",
  border: "1px solid #E2E8F0",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
};

const counterNumber = {
  fontSize: "23px",
  fontWeight: "800",
  color: "#3949AB",
};

const counterLabel = {
  fontSize: "11px",
  color: "#718096",
};

// =====================================================
// SESIÓN ACTIVA
// =====================================================
const activeSessionBox = {
  marginBottom: "18px",
  background: "#F0FFF4",
  border: "1px solid #9AE6B4",
  borderRadius: "15px",
  padding: "14px 16px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "14px",
  flexWrap: "wrap",
};

const activeSessionInfo = {
  flex: 1,
  minWidth: "220px",
};

const activeSessionTitle = {
  color: "#276749",
  fontSize: "13px",
  fontWeight: "800",
};

const activeSessionText = {
  marginTop: "4px",
  color: "#4A5568",
  fontSize: "11px",
  lineHeight: "1.5",
};

const activeSessionButton = {
  border: "none",
  background: "#38A169",
  color: "#ffffff",
  padding: "9px 14px",
  borderRadius: "9px",
  cursor: "pointer",
  fontSize: "11px",
  fontWeight: "800",
};

const activeSessionCard = {
  border: "1px solid #9AE6B4",
};

const activeBadge = {
  display: "inline-block",
  marginTop: "4px",
  marginLeft: "6px",
  padding: "3px 7px",
  borderRadius: "7px",
  background: "#F0FFF4",
  color: "#2F855A",
  fontSize: "9px",
  fontWeight: "800",
};

const activeHint = {
  marginTop: "7px",
  color: "#718096",
  fontSize: "11px",
};

// =====================================================
// NUEVA SESIÓN
// =====================================================
const newSessionSection = {
  marginBottom: "22px",
};

const newSessionButton = {
  border: "none",
  background:
    "linear-gradient(135deg, #3949AB, #42A5F5)",
  color: "#ffffff",
  padding: "12px 20px",
  borderRadius: "12px",
  cursor: "pointer",
  fontWeight: "800",
  fontSize: "13px",
  boxShadow:
    "0 6px 18px rgba(57,73,171,0.20)",
};

const disabledNewSessionButton = {
  opacity: 0.6,
  cursor: "not-allowed",
  background: "#94A3B8",
  boxShadow: "none",
};

const newSessionCard = {
  marginTop: "12px",
  background: "#ffffff",
  border: "1px solid #DDE7F5",
  borderRadius: "16px",
  padding: "18px",
  boxShadow:
    "0 7px 22px rgba(30,70,120,0.08)",
};

const newSessionTitle = {
  margin: 0,
  color: "#173B70",
  fontSize: "17px",
  fontWeight: "800",
};

const newSessionText = {
  margin: "4px 0 15px",
  color: "#718096",
  fontSize: "12px",
};

const modalityGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap: "12px",
};

const modalityCard = {
  border: "1px solid #E2E8F0",
  background: "#F8FAFC",
  borderRadius: "13px",
  padding: "15px",
  cursor: "pointer",
  textAlign: "left",
  display: "flex",
  alignItems: "center",
  gap: "12px",
};

const modalityCardSelected = {
  border: "2px solid #42A5F5",
  background: "#EEF6FF",
};

const modalityIcon = {
  width: "42px",
  height: "42px",
  minWidth: "42px",
  borderRadius: "11px",
  background: "#ffffff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "20px",
};

const modalityTitle = {
  color: "#173B70",
  fontWeight: "800",
  fontSize: "13px",
};

const modalityText = {
  marginTop: "3px",
  color: "#718096",
  fontSize: "10px",
};

const newSessionActions = {
  marginTop: "16px",
  display: "flex",
  justifyContent: "flex-end",
  gap: "9px",
  flexWrap: "wrap",
};

const cancelSessionButton = {
  border: "1px solid #CBD5E1",
  background: "#ffffff",
  color: "#64748B",
  padding: "10px 15px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "700",
};

const startSessionButton = {
  border: "none",
  background: "#3949AB",
  color: "#ffffff",
  padding: "10px 17px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "800",
};

const disabledButton = {
  opacity: 0.6,
  cursor: "not-allowed",
};

const successBox = {
  marginTop: "10px",
  background: "#F0FFF4",
  border: "1px solid #C6F6D5",
  color: "#276749",
  padding: "11px 14px",
  borderRadius: "11px",
  fontSize: "12px",
  fontWeight: "700",
};

const modalityBadge = {
  display: "inline-block",
  marginTop: "4px",
  padding: "3px 7px",
  borderRadius: "7px",
  background: "#EEF4FF",
  color: "#3949AB",
  fontSize: "9px",
  fontWeight: "800",
};

// =====================================================
// SESIONES
// =====================================================
const sessionsList = {
  display: "flex",
  flexDirection: "column",
  gap: "12px",
};

const sessionCard = {
  background: "#ffffff",
  borderRadius: "16px",
  border: "1px solid #E2E8F0",
  boxShadow:
    "0 5px 16px rgba(30,70,120,0.06)",
  overflow: "hidden",
};

const sessionCardOpen = {
  boxShadow:
    "0 8px 24px rgba(30,70,120,0.10)",
  border: "1px solid #C7D7F5",
};

const sessionHeaderButton = {
  width: "100%",
  display: "flex",
  alignItems: "center",
  gap: "13px",
  border: "none",
  background: "transparent",
  padding: "14px 16px",
  cursor: "pointer",
  textAlign: "left",
};

const sessionNumber = {
  width: "42px",
  height: "42px",
  minWidth: "42px",
  borderRadius: "12px",
  background:
    "linear-gradient(135deg, #5C6BC0, #42A5F5)",
  color: "#ffffff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "16px",
  fontWeight: "800",
};

const sessionMainInfo = {
  flex: 1,
  minWidth: 0,
};

const sessionLabel = {
  fontSize: "8px",
  fontWeight: "800",
  letterSpacing: "1.3px",
  color: "#94A3B8",
};

const sessionTitle = {
  margin: "2px 0",
  color: "#173B70",
  fontSize: "16px",
  fontWeight: "750",
};

const sessionDate = {
  color: "#718096",
  fontSize: "11px",
};

const expandButton = {
  display: "flex",
  alignItems: "center",
  gap: "6px",
  padding: "8px 11px",
  borderRadius: "9px",
  background: "#EEF4FF",
  color: "#3949AB",
  fontSize: "11px",
  fontWeight: "700",
  whiteSpace: "nowrap",
};

const expandButtonOpen = {
  background: "#E3F2FD",
  color: "#1565C0",
};

const arrow = {
  fontSize: "9px",
};

const details = {
  borderTop: "1px solid #EDF2F7",
  background: "#FAFCFF",
  padding: "14px",
  display: "grid",
  gridTemplateColumns:
    "repeat(3, minmax(0, 1fr))",
  gap: "10px",
};

const detailItem = {
  display: "flex",
  alignItems: "center",
  gap: "9px",
  background: "#ffffff",
  border: "1px solid #E8EEF5",
  borderRadius: "11px",
  padding: "10px 11px",
  minHeight: "54px",
};

const detailIcon = {
  width: "32px",
  height: "32px",
  minWidth: "32px",
  borderRadius: "9px",
  background: "#EEF4FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "15px",
};

const detailLabel = {
  fontSize: "8px",
  color: "#94A3B8",
  fontWeight: "700",
  textTransform: "uppercase",
};

const detailValue = {
  marginTop: "2px",
  color: "#334155",
  fontSize: "12px",
  fontWeight: "700",
};

const notesBox = {
  gridColumn: "1 / -1",
  background: "#ffffff",
  border: "1px solid #E8EEF5",
  borderRadius: "11px",
  padding: "12px 13px",
};

const notesTitle = {
  color: "#475569",
  fontSize: "11px",
  fontWeight: "800",
  marginBottom: "5px",
};

const notesText = {
  margin: 0,
  color: "#64748B",
  fontSize: "12px",
  lineHeight: "1.5",
  whiteSpace: "pre-wrap",
};

// =====================================================
// NOTAS PARA PREANÁLISIS IA
// =====================================================
const aiNotesBox = { gridColumn: "1 / -1", background: "#FFFDF7", border: "1px solid #F4D99B", borderRadius: "12px", padding: "14px" };
const aiNotesHeader = { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "12px", marginBottom: "10px", flexWrap: "wrap" };
const aiNotesTitle = { color: "#7A5A16", fontSize: "12px", fontWeight: "800" };
const aiNotesText = { marginTop: "4px", color: "#718096", fontSize: "10px", lineHeight: "1.5" };
const aiNotesOptional = { background: "#FFF7D6", color: "#8A6A18", padding: "4px 8px", borderRadius: "7px", fontSize: "9px", fontWeight: "800" };
const aiNotesTextarea = { width: "100%", minHeight: "130px", resize: "vertical", boxSizing: "border-box", border: "1px solid #D9C68C", borderRadius: "10px", padding: "11px 12px", fontSize: "12px", lineHeight: "1.55", color: "#334155", background: "#FFFFFF", outline: "none", fontFamily: "inherit" };
const aiNotesActions = { marginTop: "10px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px", flexWrap: "wrap" };
const aiNotesStatus = { color: "#718096", fontSize: "10px", lineHeight: "1.4", flex: 1 };
const aiNotesButton = { border: "none", background: "#B7791F", color: "#FFFFFF", padding: "9px 14px", borderRadius: "9px", cursor: "pointer", fontSize: "10px", fontWeight: "800" };
const aiNotesLoading = { padding: "12px", borderRadius: "9px", background: "#FFF9E8", color: "#8A6A18", fontSize: "11px" };

// =====================================================
// AUDIO PRESENCIAL
// =====================================================
const audioRecorderBox = {
  gridColumn: "1 / -1",
  background: "#F7FFFB",
  border: "1px solid #B7E4C7",
  borderRadius: "12px",
  padding: "14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "14px",
  flexWrap: "wrap",
};

const audioRecorderInfo = { flex: 1, minWidth: "220px" };
const audioRecorderTitle = { color: "#237A57", fontSize: "12px", fontWeight: "800" };
const audioRecorderText = { marginTop: "4px", color: "#718096", fontSize: "10px", lineHeight: "1.5" };
const audioPlayer = { width: "100%", display: "block" };

// =====================================================
// ESTADO DE TRANSCRIPCIÓN
// =====================================================
const transcriptionStatusBox = {
  marginTop: "10px",
  paddingTop: "10px",
  borderTop: "1px solid #E8EEF5",
};

const transcriptionStatusRow = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "10px",
  flexWrap: "wrap",
};

const transcriptionStatusBadge = {
  display: "inline-flex",
  alignItems: "center",
  padding: "6px 9px",
  borderRadius: "8px",
  fontSize: "10px",
  fontWeight: "800",
};

const transcriptionStatusPending = {
  background: "#FFF8E1",
  color: "#8A6A18",
};

const transcriptionStatusProcessing = {
  background: "#EEF4FF",
  color: "#3155A4",
};

const transcriptionStatusCompleted = {
  background: "#F0FFF4",
  color: "#2F855A",
};

const transcriptionStatusError = {
  background: "#FFF5F5",
  color: "#C53030",
};

const retryTranscriptionButton = {
  border: "none",
  background: "#3949AB",
  color: "#FFFFFF",
  padding: "7px 11px",
  borderRadius: "8px",
  cursor: "pointer",
  fontSize: "10px",
  fontWeight: "800",
};

const transcriptionReadyText = {
  marginTop: "7px",
  color: "#2F855A",
  fontSize: "10px",
  lineHeight: "1.45",
};

const transcriptionProcessingText = {
  marginTop: "7px",
  color: "#4A5568",
  fontSize: "10px",
  lineHeight: "1.45",
};

const transcriptionErrorText = {
  marginTop: "7px",
  color: "#718096",
  fontSize: "10px",
  lineHeight: "1.45",
};

// =====================================================
// PRUEBAS PSICOLÓGICAS DE LA SESIÓN
// =====================================================
const sessionTestsBox = {
  gridColumn: "1 / -1",
  background: "#F7FAFF",
  border: "1px solid #C7D7F5",
  borderRadius: "12px",
  padding: "14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "14px",
  flexWrap: "wrap",
};

const sessionTestsInfo = {
  flex: 1,
  minWidth: "220px",
};

const sessionTestsTitle = {
  color: "#3949AB",
  fontSize: "12px",
  fontWeight: "800",
};

const sessionTestsText = {
  marginTop: "4px",
  color: "#718096",
  fontSize: "10px",
  lineHeight: "1.5",
};

const sessionTestsButton = {
  border: "none",
  background: "#3949AB",
  color: "#ffffff",
  padding: "10px 16px",
  borderRadius: "10px",
  cursor: "pointer",
  fontSize: "11px",
  fontWeight: "800",
};

// =====================================================
// TERMINAR CONSULTA
// =====================================================
const finishConsultationBox = {
  gridColumn: "1 / -1",
  background: "#FFFDF5",
  border: "1px solid #F6E05E",
  borderRadius: "12px",
  padding: "14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "14px",
  flexWrap: "wrap",
};

const finishConsultationInfo = {
  flex: 1,
  minWidth: "220px",
};

const finishConsultationTitle = {
  color: "#744210",
  fontSize: "12px",
  fontWeight: "800",
};

const finishConsultationText = {
  marginTop: "4px",
  color: "#718096",
  fontSize: "10px",
  lineHeight: "1.5",
};

const finishConsultationButton = {
  border: "none",
  background: "#D69E2E",
  color: "#ffffff",
  padding: "10px 16px",
  borderRadius: "10px",
  cursor: "pointer",
  fontSize: "11px",
  fontWeight: "800",
};

// =====================================================
// MULTIMEDIA
// =====================================================
const multimediaBox = {
  gridColumn: "1 / -1",
  background: "#ffffff",
  border: "1px solid #E1E8F0",
  borderRadius: "12px",
  padding: "12px",
};

const multimediaHeader = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "10px",
  marginBottom: "8px",
};

const multimediaTitle = {
  color: "#334155",
  fontSize: "12px",
  fontWeight: "800",
};

const multimediaSubtitle = {
  marginTop: "2px",
  color: "#94A3B8",
  fontSize: "10px",
};

const multimediaCount = {
  background: "#EEF4FF",
  color: "#3949AB",
  padding: "4px 8px",
  borderRadius: "7px",
  fontSize: "9px",
  fontWeight: "700",
  whiteSpace: "nowrap",
};

const multimediaLoadingBox = {
  padding: "11px",
  borderRadius: "9px",
  background: "#F8FAFC",
  color: "#64748B",
  fontSize: "11px",
};

const multimediaEmptyBox = {
  display: "flex",
  alignItems: "center",
  gap: "8px",
  padding: "10px",
  borderRadius: "9px",
  background: "#F8FAFC",
  color: "#94A3B8",
  fontSize: "11px",
};

const multimediaEmptyIcon = {
  fontSize: "16px",
};

const videosList = {
  display: "flex",
  flexDirection: "column",
  gap: "8px",
};

const videoWrapper = {
  background: "#F8FAFC",
  border: "1px solid #E2E8F0",
  borderRadius: "10px",
  padding: "9px",
};

const videoHeader = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "8px",
  marginBottom: "7px",
};

const videoHeaderInfo = {
  minWidth: 0,
};

const videoName = {
  color: "#334155",
  fontSize: "11px",
  fontWeight: "700",
};

const videoDate = {
  marginTop: "2px",
  color: "#94A3B8",
  fontSize: "9px",
};

const videoType = {
  background: "#E3F2FD",
  color: "#1565C0",
  padding: "4px 7px",
  borderRadius: "6px",
  fontSize: "8px",
  fontWeight: "700",
  textTransform: "uppercase",
};

const videoPlayerContainer = {
  width: "100%",
  overflow: "hidden",
  borderRadius: "8px",
  background: "#000",
};

const videoPlayer = {
  width: "100%",
  maxHeight: "360px",
  minHeight: "200px",
  display: "block",
  background: "#000",
};

// =====================================================
// PAGINACIÓN
// =====================================================
const paginationContainer = {
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  gap: "10px",
  flexWrap: "wrap",
  marginTop: "18px",
};

const moreButton = {
  display: "flex",
  alignItems: "center",
  gap: "7px",
  border: "1px solid #C7D7F5",
  background: "#ffffff",
  color: "#1565C0",
  padding: "10px 16px",
  borderRadius: "11px",
  cursor: "pointer",
  fontWeight: "700",
  fontSize: "11px",
  boxShadow:
    "0 4px 12px rgba(21,101,192,0.07)",
};

const moreButtonIcon = {
  fontSize: "16px",
  fontWeight: "800",
};

const remainingText = {
  color: "#94A3B8",
  fontWeight: "500",
  fontSize: "10px",
};

const lessButton = {
  display: "flex",
  alignItems: "center",
  gap: "6px",
  border: "none",
  background: "#EEF4FF",
  color: "#3949AB",
  padding: "9px 15px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "700",
  fontSize: "11px",
};

// =====================================================
// SIN SESIONES
// =====================================================
const emptyBox = {
  background: "#ffffff",
  borderRadius: "17px",
  padding: "40px 22px",
  textAlign: "center",
  border: "1px solid #E2E8F0",
  boxShadow:
    "0 7px 20px rgba(30,70,120,0.06)",
};

const emptyIcon = {
  fontSize: "42px",
  marginBottom: "8px",
};

const emptyTitle = {
  margin: "0 0 6px",
  color: "#173B70",
  fontSize: "18px",
};

const emptyText = {
  margin: 0,
  color: "#718096",
  fontSize: "13px",
};

// =====================================================
// ERROR
// =====================================================
const errorBox = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: "8px",
  background: "#FFF5F5",
  color: "#C53030",
  border: "1px solid #FED7D7",
  borderRadius: "13px",
  padding: "14px",
  fontSize: "12px",
};

// =====================================================
// VOLVER
// =====================================================
const backContainer = {
  marginTop: "22px",
  display: "flex",
  justifyContent: "center",
};

const backButton = {
  border: "none",
  background: "#E3F2FD",
  color: "#1565C0",
  padding: "10px 19px",
  borderRadius: "11px",
  cursor: "pointer",
  fontWeight: "700",
  fontSize: "12px",
  boxShadow:
    "0 4px 12px rgba(21,101,192,0.08)",
};

// =====================================================
// LOADING
// =====================================================
const loadingPage = {
  minHeight: "100vh",
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  background:
    "linear-gradient(135deg, #eef6ff, #f8fbff)",
  padding: "20px",
  boxSizing: "border-box",
};

const loadingCard = {
  background: "#ffffff",
  padding: "38px",
  borderRadius: "18px",
  textAlign: "center",
  boxShadow:
    "0 10px 28px rgba(30,70,120,0.09)",
};

const loadingIcon = {
  fontSize: "36px",
  marginBottom: "8px",
};

const loadingTitle = {
  margin: "0 0 7px",
  color: "#173B70",
};

const loadingText = {
  margin: 0,
  color: "#718096",
  fontSize: "13px",
};

// =====================================================
// FOOTER
// =====================================================
const footer = {
  borderTop: "1px solid #E2E8F0",
  marginTop: "28px",
  paddingTop: "15px",
  display: "flex",
  justifyContent: "space-between",
  color: "#94A3B8",
  fontSize: "11px",
};