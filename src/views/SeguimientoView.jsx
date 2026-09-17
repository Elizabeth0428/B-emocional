// src/views/SeguimientoView.jsx

import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

export default function SeguimientoView() {

  const { idPaciente, idSesion } = useParams();
  const navigate = useNavigate();
  const modoCierre = Boolean(idSesion);

  const [seguimientos, setSeguimientos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [preanalisis, setPreanalisis] = useState(null);
  const [loadingPreanalisis, setLoadingPreanalisis] = useState(false);
  const [guardando, setGuardando] = useState(false);
  const [sesiones, setSesiones] = useState([]);
  const [reportesIA, setReportesIA] = useState([]);
  const [resultadosPruebas, setResultadosPruebas] = useState([]);
  const [archivosPorSesion, setArchivosPorSesion] = useState({});
  const [notasIAPorSesion, setNotasIAPorSesion] = useState({});
  const [sesionesAbiertas, setSesionesAbiertas] = useState({});
  const [reportesAbiertos, setReportesAbiertos] = useState({});

  const [nuevo, setNuevo] = useState({
    diagnostico: "",
    tratamiento: "",
    evolucion: "",
    observaciones: "",
    tareas_acuerdos: "",
  });


  // =====================================================
  // OBTENER SEGUIMIENTOS
  // =====================================================

  useEffect(() => {

    const fetchSeguimiento = async () => {

      try {

        const res = await fetch(
          `http://localhost:5000/api/seguimiento/${idPaciente}`,
          {
            headers: {
              Authorization: `Bearer ${getToken()}`
            }
          }
        );


        if (res.ok) {

          const data = await res.json();

          setSeguimientos(
            Array.isArray(data)
              ? data
              : []
          );

        }

      } catch (err) {

        console.error(
          "❌ Error al obtener seguimientos:",
          err
        );

      } finally {

        setLoading(false);

      }

    };


    fetchSeguimiento();

  }, [idPaciente]);


  // =====================================================
  // OBTENER PREANÁLISIS IA DE LA SESIÓN
  // =====================================================

  useEffect(() => {
    if (!modoCierre || !idSesion) {
      setPreanalisis(null);
      return;
    }

    const fetchPreanalisis = async () => {
      setLoadingPreanalisis(true);

      try {
        const res = await fetch(
          `http://localhost:5000/api/reportes/paciente/${idPaciente}`,
          {
            headers: {
              Authorization: `Bearer ${getToken()}`
            }
          }
        );

        if (!res.ok) {
          throw new Error("No se pudo obtener el Preanálisis IA");
        }

        const data = await res.json();
        const reportes = Array.isArray(data) ? data : [];
        const reportesSesion = reportes
          .filter((r) => Number(r.id_sesion) === Number(idSesion))
          .sort((a, b) => new Date(b.fecha || 0) - new Date(a.fecha || 0));

        setPreanalisis(reportesSesion[0] || null);

      } catch (err) {
        console.error("❌ Error al obtener Preanálisis IA:", err);
        setPreanalisis(null);
      } finally {
        setLoadingPreanalisis(false);
      }
    };

    fetchPreanalisis();
  }, [idPaciente, idSesion, modoCierre]);


  // =====================================================
  // HISTORIAL CLÍNICO CENTRALIZADO POR SESIONES
  // =====================================================
  useEffect(() => {
    if (modoCierre) return;

    const cargarHistorialClinico = async () => {
      try {
        const headers = { Authorization: `Bearer ${getToken()}` };

        const [resSesiones, resReportes, resResultados] = await Promise.all([
          fetch(`http://localhost:5000/api/sesiones/paciente/${idPaciente}`, { headers }),
          fetch(`http://localhost:5000/api/reportes/paciente/${idPaciente}`, { headers }),
          fetch(`http://localhost:5000/api/evaluation/resultados/${idPaciente}`, { headers })
        ]);

        const dataSesiones = resSesiones.ok ? await resSesiones.json() : [];
        const dataReportes = resReportes.ok ? await resReportes.json() : [];
        const dataResultados = resResultados.ok ? await resResultados.json() : [];

        const listaSesiones = Array.isArray(dataSesiones) ? dataSesiones : [];
        setSesiones(listaSesiones);
        setReportesIA(Array.isArray(dataReportes) ? dataReportes : []);
        setResultadosPruebas(Array.isArray(dataResultados) ? dataResultados : []);

        const pares = await Promise.all(
          listaSesiones.map(async (sesion) => {
            try {
              const res = await fetch(
                `http://localhost:5000/api/archivos/sesion/${sesion.id_sesion}`,
                { headers }
              );
              const data = res.ok ? await res.json() : [];
              return [sesion.id_sesion, Array.isArray(data) ? data : []];
            } catch {
              return [sesion.id_sesion, []];
            }
          })
        );

        setArchivosPorSesion(Object.fromEntries(pares));

        const notasPares = await Promise.all(
          listaSesiones.map(async (sesion) => {
            try {
              const res = await fetch(
                `http://localhost:5000/api/notas/ia/${sesion.id_sesion}`,
                { headers }
              );
              if (!res.ok) {
                console.warn(`⚠️ No se pudo cargar nota IA de sesión #${sesion.id_sesion}:`, res.status);
                return [sesion.id_sesion, null];
              }

              const data = await res.json();
              const candidato = data?.nota ?? data?.data ?? data;
              let nota = null;

              if (typeof candidato === "string") {
                nota = { nota: candidato, fecha: data?.fecha || null };
              } else if (candidato && typeof candidato === "object") {
                const texto = candidato.nota ?? candidato.pregunta ?? candidato.respuesta ?? "";
                nota = texto ? { ...candidato, nota: texto } : null;
              }

              console.log(`📝 Nota IA sesión #${sesion.id_sesion}:`, nota);
              return [sesion.id_sesion, nota];
            } catch {
              return [sesion.id_sesion, null];
            }
          })
        );

        setNotasIAPorSesion(Object.fromEntries(notasPares));
      } catch (err) {
        console.error("❌ Error al cargar historial clínico por sesiones:", err);
      }
    };

    cargarHistorialClinico();
  }, [idPaciente, modoCierre]);

  const toggleSesion = (id) => {
    setSesionesAbiertas((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleReporte = (id) => {
    setReportesAbiertos((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const obtenerSeguimientoSesion = (id) =>
    seguimientos
      .filter((seg) => Number(seg.id_sesion) === Number(id))
      .sort((a, b) => new Date(b.fecha || 0) - new Date(a.fecha || 0))[0] || null;

  const obtenerReporteSesion = (id) =>
    reportesIA
      .filter((r) => Number(r.id_sesion) === Number(id))
      .sort((a, b) => new Date(b.fecha || 0) - new Date(a.fecha || 0))[0] || null;

  const obtenerResultadosSesion = (id) =>
    resultadosPruebas.filter((r) => Number(r.id_sesion) === Number(id));

  const abrirPDFReporte = (idReporte) => {
    window.open(`http://localhost:5000/api/reportes/${idReporte}/pdf`, "_blank");
  };

  const formatearFecha = (fecha) => {
    if (!fecha) return "Fecha no registrada";
    const d = new Date(fecha);
    if (Number.isNaN(d.getTime())) return "Fecha no registrada";
    return d.toLocaleDateString("es-MX", {
      day: "2-digit",
      month: "long",
      year: "numeric"
    });
  };

  const formatearHora = (fecha) => {
    if (!fecha) return "";
    const d = new Date(fecha);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit" });
  };

  // =====================================================
  // VOLVER AL EXPEDIENTE
  // =====================================================

  const volverAlExpediente = () => {
    navigate(
      modoCierre
        ? `/paciente/${idPaciente}/sesiones`
        : `/paciente/${idPaciente}`
    );
  };


  // =====================================================
  // AGREGAR SEGUIMIENTO
  // =====================================================

  const handleAdd = async () => {
    if (guardando) return;

    try {
      if (
        !nuevo.diagnostico &&
        !nuevo.tratamiento &&
        !nuevo.evolucion &&
        !nuevo.observaciones &&
        !nuevo.tareas_acuerdos
      ) {
        alert(
          modoCierre
            ? "⚠️ Escribe al menos un dato para completar el cierre clínico."
            : "⚠️ Escribe al menos un dato del seguimiento."
        );
        return;
      }

      setGuardando(true);

      const res = await fetch(
        "http://localhost:5000/api/seguimiento",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${getToken()}`
          },
          body: JSON.stringify({
            ...nuevo,
            id_paciente: Number(idPaciente),
            id_sesion: modoCierre ? Number(idSesion) : null
          })
        }
      );

      if (!res.ok) {
        throw new Error("Error al guardar seguimiento");
      }

      const data = await res.json();

      if (modoCierre) {
        const resFinalizar = await fetch(
          `http://localhost:5000/api/sesiones/${idSesion}/finalizar`,
          {
            method: "PUT",
            headers: {
              Authorization: `Bearer ${getToken()}`
            }
          }
        );

        if (!resFinalizar.ok) {
          const errorFinalizar = await resFinalizar.json().catch(() => ({}));
          throw new Error(
            errorFinalizar.message ||
            "El cierre clínico se guardó, pero no se pudo finalizar la sesión."
          );
        }

        const agendarAhora = window.confirm(
          `✅ Cierre clínico guardado y sesión #${idSesion} finalizada correctamente.\n\n📅 ¿Deseas agendar ahora la próxima consulta de este paciente?\n\nAceptar = Agendar ahora\nCancelar = Ahora no`
        );

        if (agendarAhora) {
          navigate(
            `/citas?paciente=${idPaciente}&tipo=consulta&nueva=1&sesionOrigen=${idSesion}`
          );
        } else {
          navigate(`/paciente/${idPaciente}/sesiones`);
        }

        return;
      }

      setSeguimientos([
        {
          ...nuevo,
          id_seguimiento: data.id_seguimiento,
          fecha: new Date(),
          id_sesion: null
        },
        ...seguimientos
      ]);

      setNuevo({
        diagnostico: "",
        tratamiento: "",
        evolucion: "",
        observaciones: "",
        tareas_acuerdos: ""
      });

      alert("✅ Seguimiento agregado correctamente");

    } catch (err) {
      console.error("❌ Error:", err);
      alert(`❌ ${err.message || "No se pudo guardar el seguimiento"}`);
    } finally {
      setGuardando(false);
    }
  };


  // =====================================================
  // CARGANDO
  // =====================================================

  if (loading) {

    return (

      <div style={loadingPage}>

        <div style={loadingCard}>

          <div style={loadingIcon}>
            ⏳
          </div>

          <h2 style={loadingTitle}>
            Cargando seguimiento...
          </h2>

          <p style={loadingText}>
            Estamos obteniendo la información clínica
            del paciente.
          </p>

        </div>

      </div>

    );

  }


  // =====================================================
  // RENDER
  // =====================================================

  return (

    <div style={page}>

      <div style={container}>


        {/* =================================================
            ENCABEZADO
        ================================================= */}

        <div style={header}>

          <button
            type="button"
            onClick={volverAlExpediente}
            style={backButton}
          >
            {modoCierre ? "← Volver a sesiones" : "← Volver al expediente"}
          </button>


          <div style={headerContent}>

            <div style={headerIcon}>
              📑
            </div>

            <div>

              <div style={eyebrow}>
                {modoCierre ? `CIERRE DE SESIÓN #${idSesion}` : "EXPEDIENTE DEL PACIENTE"}
              </div>

              <h1 style={title}>
                {modoCierre ? `Cierre Clínico — Sesión #${idSesion}` : "Seguimiento Clínico"}
              </h1>

              <p style={subtitle}>
                {modoCierre
                  ? "Completa la valoración profesional de esta consulta. El registro quedará vinculado a esta sesión."
                  : "Registra y consulta la evolución clínica del paciente."}
              </p>

            </div>

          </div>

        </div>


        {/* =================================================
            PACIENTE
        ================================================= */}

        <div style={patientBar}>

          <div style={patientBarIcon}>
            👤
          </div>

          <div>

            <span style={patientLabel}>
              Paciente
            </span>

            <strong style={patientId}>
              Expediente #{idPaciente}
              {modoCierre ? ` · Sesión #${idSesion}` : ""}
            </strong>

          </div>

        </div>


        {modoCierre && (
          <section style={preanalisisSection}>
            <div style={sectionHeader}>
              <div>
                <h2 style={sectionTitle}>🤖 Preanálisis IA — Sesión #{idSesion}</h2>
                <p style={sectionDescription}>
                  Apoyo clínico generado con la información de esta sesión. Debe ser revisado por el profesional y no sustituye su valoración clínica.
                </p>
              </div>
              <div style={aiBadge}>APOYO IA</div>
            </div>

            {loadingPreanalisis ? (
              <div style={preanalisisEmpty}>⏳ Cargando Preanálisis IA...</div>
            ) : preanalisis?.contenido ? (
              <div style={preanalisisContent}>{preanalisis.contenido}</div>
            ) : (
              <div style={preanalisisEmpty}>
                ⚠️ No se encontró un Preanálisis IA asociado a la sesión #{idSesion}.
              </div>
            )}
          </section>
        )}


        {/* =================================================
            NUEVO SEGUIMIENTO / CIERRE
        ================================================= */}

        {modoCierre && (
        <section style={section}>

          <div style={sectionHeader}>

            <div>

              <h2 style={sectionTitle}>
                {modoCierre ? "📝 Completar cierre clínico" : "➕ Registrar nuevo seguimiento"}
              </h2>

              <p style={sectionDescription}>
                {modoCierre
                  ? `Registra la conclusión profesional correspondiente a la sesión #${idSesion}.`
                  : "Agrega información sobre la evolución clínica del paciente."}
              </p>

            </div>

          </div>


          <div style={formGrid}>

            <div style={field}>

              <label style={label}>
                {modoCierre ? "🩺 Diagnóstico / impresión clínica" : "🩺 Diagnóstico"}
              </label>

              <textarea
                placeholder="Escribe el diagnóstico..."
                value={nuevo.diagnostico}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    diagnostico:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>


            <div style={field}>

              <label style={label}>
                {modoCierre ? "💊 Tratamiento / intervención" : "💊 Tratamiento"}
              </label>

              <textarea
                placeholder="Describe el tratamiento..."
                value={nuevo.tratamiento}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    tratamiento:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>


            <div style={field}>

              <label style={label}>
                📈 Evolución
              </label>

              <textarea
                placeholder="Describe la evolución del paciente..."
                value={nuevo.evolucion}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    evolucion:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>


            <div style={field}>

              <label style={label}>
                📝 Observaciones
              </label>

              <textarea
                placeholder="Agrega observaciones..."
                value={nuevo.observaciones}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    observaciones:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>


            <div style={fullWidthField}>

              <label style={label}>
                📌 Tareas / acuerdos para la próxima sesión
              </label>

              <textarea
                placeholder="Registra tareas, compromisos, ejercicios o acuerdos para dar seguimiento en la próxima sesión..."
                value={nuevo.tareas_acuerdos}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    tareas_acuerdos: e.target.value
                  })
                }
                style={textarea}
              />

            </div>

          </div>


          <div style={formActions}>

            <button
              type="button"
              style={{
                ...saveButton,
                ...(guardando ? disabledButton : {})
              }}
              onClick={handleAdd}
              disabled={guardando}
            >
              {guardando
                ? "⏳ Guardando..."
                : modoCierre
                  ? "💾 Guardar y finalizar sesión"
                  : "💾 Guardar seguimiento"}
            </button>

          </div>

        </section>
        )}


        {/* =================================================
            HISTORIAL CLÍNICO POR SESIONES
        ================================================= */}

        {!modoCierre && (
          <section style={section}>
            <div style={sectionHeader}>
              <div>
                <h2 style={sectionTitle}>📋 Historial clínico por sesiones</h2>
                <p style={sectionDescription}>
                  Consulta en un solo lugar todo lo registrado durante cada sesión del paciente.
                </p>
              </div>
              <div style={counter}>
                <strong>{sesiones.length}</strong>
                <span>sesiones</span>
              </div>
            </div>

            {sesiones.length > 0 ? (
              <div style={sessionList}>
                {[...sesiones]
                  .sort((a, b) => new Date(b.fecha || 0) - new Date(a.fecha || 0))
                  .map((sesion) => {
                    const id = sesion.id_sesion;
                    const abierta = Boolean(sesionesAbiertas[id]);
                    const seguimiento = obtenerSeguimientoSesion(id);
                    const reporte = obtenerReporteSesion(id);
                    const pruebas = obtenerResultadosSesion(id);
                    const archivos = archivosPorSesion[id] || [];
                    const transcripciones = archivos.filter(
                      (archivo) =>
                        archivo.transcripcion_estado === "completada" &&
                        typeof archivo.transcripcion === "string" &&
                        archivo.transcripcion.trim()
                    );
                    const notaIA = notasIAPorSesion[id] || null;

                    return (
                      <div key={id} style={sessionCard}>
                        <button
                          type="button"
                          onClick={() => toggleSesion(id)}
                          style={sessionHeaderButton}
                        >
                          <div style={sessionHeaderLeft}>
                            <div style={sessionNumber}>🧠 Sesión #{id}</div>
                            <div style={sessionMeta}>
                              📅 {formatearFecha(sesion.fecha)}
                              {formatearHora(sesion.fecha) ? ` · ${formatearHora(sesion.fecha)}` : ""}
                              {" · "}
                              {sesion.modalidad || "Modalidad no registrada"}
                            </div>
                          </div>
                          <div style={sessionHeaderRight}>
                            <span style={sesion.estado === "finalizada" ? statusFinalizada : statusActiva}>
                              {sesion.estado === "finalizada" ? "✓ Finalizada" : "● Activa"}
                            </span>
                            <span style={openButton}>{abierta ? "Cerrar ▲" : "Abrir sesión ▼"}</span>
                          </div>
                        </button>

                        {!abierta && seguimiento && (
                          <div style={sessionSummary}>
                            <strong>Último cierre:</strong>{" "}
                            {seguimiento.diagnostico || seguimiento.evolucion || "Información clínica registrada"}
                          </div>
                        )}

                        {abierta && (
                          <div style={sessionBody}>
                            <ClinicalSection icon="📅" title="Información de la sesión">
                              <div style={detailGrid}>
                                <MiniDetail label="Fecha" value={formatearFecha(sesion.fecha)} />
                                <MiniDetail label="Hora" value={formatearHora(sesion.fecha) || "No registrada"} />
                                <MiniDetail label="Modalidad" value={sesion.modalidad || "No registrada"} />
                                <MiniDetail label="Estado" value={sesion.estado || "No registrado"} />
                              </div>
                              <div style={notesBox}>
                                <strong>Notas de la sesión</strong>
                                <div>{sesion.notas || "No se registraron notas en esta sesión."}</div>
                              </div>
                            </ClinicalSection>

                            {notaIA && (notaIA.nota || notaIA.pregunta) && (
                              <ClinicalSection icon="📝" title="Nota clínica para IA">
                                <div style={notesBox}>
                                  <div>{notaIA.nota || notaIA.pregunta}</div>
                                  {notaIA.fecha && (
                                    <div style={mutedText}>
                                      Guardada: {formatearFecha(notaIA.fecha)}
                                    </div>
                                  )}
                                </div>
                              </ClinicalSection>
                            )}

                            <ClinicalSection icon="🧪" title="Pruebas y resultados">
                              {pruebas.length ? (
                                <div style={itemsGrid}>
                                  {pruebas.map((prueba, index) => (
                                    <div key={prueba.id_resultado || `${id}-${index}`} style={resultCard}>
                                      <strong>{prueba.prueba || prueba.nombre_prueba || prueba.nombre || `Prueba #${prueba.id_prueba || index + 1}`}</strong>
                                      <span>Puntaje: {prueba.puntaje_total ?? prueba.puntaje ?? "No registrado"}</span>
                                      <span>Interpretación: {prueba.interpretacion || "No registrada"}</span>
                                      {prueba.fecha && <small>Aplicada: {formatearFecha(prueba.fecha)}</small>}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <EmptyDetail text="No se registraron resultados de pruebas en esta sesión." />
                              )}
                            </ClinicalSection>

                            <ClinicalSection icon="🎥" title="Multimedia / grabaciones">
                              {archivos.length ? (
                                <div style={mediaList}>
                                  {archivos.map((archivo) => {
                                    const url = archivo.ruta_video?.startsWith("http")
                                      ? archivo.ruta_video
                                      : `http://localhost:5000${archivo.ruta_video || ""}`;
                                    return (
                                      <div key={archivo.id_video} style={mediaCard}>
                                        <div>
                                          <strong>{archivo.descripcion || "Archivo de sesión"}</strong>
                                          <div style={mutedText}>
                                            {archivo.tipo || "archivo"}
                                            {archivo.formato ? ` · ${archivo.formato}` : ""}
                                          </div>
                                        </div>
                                        {archivo.ruta_video && (
                                          <a href={url} target="_blank" rel="noreferrer" style={mediaLink}>
                                            ▶ Abrir
                                          </a>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              ) : (
                                <EmptyDetail text="No se registró multimedia en esta sesión." />
                              )}
                            </ClinicalSection>

                            {transcripciones.length > 0 && (
                              <ClinicalSection icon="🗣️" title="Transcripción de audio">
                                <div style={transcriptList}>
                                  {transcripciones.map((archivo, index) => (
                                    <div
                                      key={archivo.id_video || `${id}-transcripcion-${index}`}
                                      style={transcriptCard}
                                    >
                                      <div style={transcriptHeader}>
                                        <strong>
                                          {archivo.descripcion || `Audio ${index + 1}`}
                                        </strong>
                                        <span style={transcriptBadge}>USADA POR IA</span>
                                      </div>

                                      <div style={transcriptText}>
                                        {archivo.transcripcion.trim()}
                                      </div>

                                      <div style={mutedText}>
                                        {archivo.transcripcion_fecha
                                          ? `Transcrita: ${formatearFecha(archivo.transcripcion_fecha)}`
                                          : "Transcripción completada"}
                                        {archivo.transcripcion_modelo
                                          ? ` · ${archivo.transcripcion_modelo}`
                                          : ""}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </ClinicalSection>
                            )}

                            <ClinicalSection icon="🤖" title="Preanálisis IA">
                              {reporte ? (
                                <div style={aiHistoryCard}>
                                  <div style={aiHistoryTop}>
                                    <div>
                                      <strong>Preanálisis IA — Sesión #{id}</strong>
                                      <div style={mutedText}>
                                        Generado: {formatearFecha(reporte.fecha)}
                                      </div>
                                    </div>
                                    <div style={inlineActions}>
                                      <button
                                        type="button"
                                        style={secondaryButton}
                                        onClick={() => toggleReporte(reporte.id_reporte)}
                                      >
                                        {reportesAbiertos[reporte.id_reporte] ? "Ocultar ▲" : "Ver completo ▼"}
                                      </button>
                                      <button
                                        type="button"
                                        style={pdfButton}
                                        onClick={() => abrirPDFReporte(reporte.id_reporte)}
                                      >
                                        📄 PDF
                                      </button>
                                    </div>
                                  </div>
                                  {reportesAbiertos[reporte.id_reporte] && (
                                    <div style={aiExpanded}>{reporte.contenido}</div>
                                  )}
                                </div>
                              ) : (
                                <EmptyDetail text="No se encontró Preanálisis IA asociado a esta sesión." />
                              )}
                            </ClinicalSection>

                            <ClinicalSection icon="🩺" title="Cierre profesional">
                              {seguimiento ? (
                                <>
                                  <div style={infoGrid}>
                                    <InfoBlock icon="🩺" title="Diagnóstico / impresión clínica" value={seguimiento.diagnostico} />
                                    <InfoBlock icon="💊" title="Tratamiento / intervención" value={seguimiento.tratamiento} />
                                    <InfoBlock icon="📈" title="Evolución" value={seguimiento.evolucion} />
                                    <InfoBlock icon="📝" title="Observaciones" value={seguimiento.observaciones} />
                                  </div>
                                  <div style={{ marginTop: "12px" }}>
                                    <InfoBlock icon="📌" title="Tareas / acuerdos" value={seguimiento.tareas_acuerdos} />
                                  </div>
                                  <div style={closureDate}>
                                    Cierre registrado: {formatearFecha(seguimiento.fecha)}
                                  </div>
                                </>
                              ) : (
                                <EmptyDetail text="Esta sesión todavía no tiene cierre clínico registrado." />
                              )}
                            </ClinicalSection>
                          </div>
                        )}
                      </div>
                    );
                  })}
              </div>
            ) : (
              <div style={emptyState}>
                <div style={emptyIcon}>📋</div>
                <h3 style={emptyTitle}>No hay sesiones registradas</h3>
                <p style={emptyText}>
                  Cuando el paciente tenga sesiones, su información clínica aparecerá aquí organizada cronológicamente.
                </p>
              </div>
            )}
          </section>
        )}


        {/* =================================================
            PIE
        ================================================= */}

        <div style={footer}>

          <span>
            🧠 MirrorSoul
          </span>

          <button
            type="button"
            onClick={volverAlExpediente}
            style={footerLink}
          >
            {modoCierre ? "← Sesiones del paciente" : "← Expediente del paciente"}
          </button>

        </div>

      </div>

    </div>

  );

}


// =====================================================
// COMPONENTES DEL HISTORIAL POR SESIÓN
// =====================================================

function ClinicalSection({ icon, title, children }) {
  return (
    <section style={clinicalSection}>
      <h3 style={clinicalSectionTitle}>{icon} {title}</h3>
      {children}
    </section>
  );
}

function MiniDetail({ label, value }) {
  return (
    <div style={miniDetail}>
      <span style={miniLabel}>{label}</span>
      <strong style={miniValue}>{value || "No registrado"}</strong>
    </div>
  );
}

function EmptyDetail({ text }) {
  return <div style={emptyDetail}>{text}</div>;
}


// =====================================================
// COMPONENTE INFORMACIÓN
// =====================================================

function InfoBlock({
  icon,
  title,
  value
}) {

  return (

    <div style={infoBlock}>

      <div style={infoBlockTitle}>
        <span>
          {icon}
        </span>

        {title}
      </div>

      <div style={infoBlockValue}>

        {value || "No registrado"}

      </div>

    </div>

  );

}


// =====================================================
// ESTILOS
// =====================================================

const page = {

  minHeight: "100vh",

  background:
    "linear-gradient(135deg, #eef6ff 0%, #f8fbff 50%, #eef4ff 100%)",

  padding: "30px 20px 50px",

  boxSizing: "border-box"

};


const container = {

  maxWidth: "1100px",

  margin: "0 auto"

};


const header = {

  marginBottom: "22px"

};


const backButton = {

  border: "none",

  background: "#ffffff",

  color: "#3155a4",

  padding: "11px 17px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

  fontSize: "14px",

  boxShadow:
    "0 4px 14px rgba(30,70,120,0.08)",

  marginBottom: "22px"

};


const headerContent = {

  display: "flex",

  alignItems: "center",

  gap: "16px"

};


const headerIcon = {

  width: "62px",

  height: "62px",

  borderRadius: "18px",

  background:
    "linear-gradient(135deg, #5c6bc0, #42a5f5)",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "30px",

  boxShadow:
    "0 8px 20px rgba(63,81,181,0.20)"

};


const eyebrow = {

  fontSize: "11px",

  fontWeight: "800",

  letterSpacing: "2px",

  color: "#5c6bc0",

  marginBottom: "5px"

};


const title = {

  margin: 0,

  color: "#173b70",

  fontSize: "30px",

  fontWeight: "800"

};


const subtitle = {

  margin: "6px 0 0",

  color: "#718096",

  fontSize: "14px"

};


const patientBar = {

  display: "flex",

  alignItems: "center",

  gap: "12px",

  background: "#ffffff",

  border:
    "1px solid #e2e8f0",

  borderRadius: "16px",

  padding: "14px 18px",

  marginBottom: "22px",

  boxShadow:
    "0 6px 20px rgba(30,70,120,0.07)"

};


const patientBarIcon = {

  width: "40px",

  height: "40px",

  borderRadius: "12px",

  background: "#eef4ff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "19px"

};


const patientLabel = {

  display: "block",

  fontSize: "11px",

  color: "#94a3b8",

  textTransform: "uppercase",

  fontWeight: "700"

};


const patientId = {

  display: "block",

  marginTop: "2px",

  color: "#3155a4",

  fontSize: "14px"

};


const section = {

  background: "#ffffff",

  border:
    "1px solid #e2e8f0",

  borderRadius: "20px",

  padding: "25px",

  boxShadow:
    "0 8px 28px rgba(30,70,120,0.08)",

  marginBottom: "22px"

};


const sectionHeader = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  gap: "15px",

  marginBottom: "22px"

};


const sectionTitle = {

  margin: 0,

  color: "#263238",

  fontSize: "21px"

};


const sectionDescription = {

  margin: "6px 0 0",

  color: "#78909c",

  fontSize: "13px"

};


const formGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",

  gap: "16px"

};


const field = {

  display: "flex",

  flexDirection: "column"

};


const fullWidthField = {
  display: "flex",
  flexDirection: "column",
  gridColumn: "1 / -1"
};

const preanalisisSection = {
  ...section,
  border: "1px solid #cdd8ff",
  background: "linear-gradient(135deg, #ffffff 0%, #f7f8ff 100%)"
};

const aiBadge = {
  background: "#eef0ff",
  color: "#4f46b8",
  padding: "7px 11px",
  borderRadius: "10px",
  fontSize: "11px",
  fontWeight: "800",
  letterSpacing: "1px"
};

const preanalisisContent = {
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
  lineHeight: "1.7",
  color: "#334155",
  background: "#ffffff",
  border: "1px solid #e2e8f0",
  borderRadius: "14px",
  padding: "18px",
  fontSize: "14px"
};

const preanalisisEmpty = {
  background: "#f8fafc",
  border: "1px dashed #cbd5e1",
  borderRadius: "14px",
  padding: "18px",
  color: "#64748b",
  fontSize: "14px"
};

const disabledButton = {
  opacity: 0.65,
  cursor: "not-allowed"
};


const label = {

  color: "#455a64",

  fontSize: "13px",

  fontWeight: "700",

  marginBottom: "7px"

};


const textarea = {

  width: "100%",

  minHeight: "110px",

  resize: "vertical",

  boxSizing: "border-box",

  border:
    "1px solid #dbe3ec",

  borderRadius: "12px",

  padding: "12px",

  fontFamily:
    "'Segoe UI', sans-serif",

  fontSize: "14px",

  color: "#263238",

  outline: "none",

  background: "#f8fafc"

};


const formActions = {

  display: "flex",

  justifyContent: "flex-end",

  marginTop: "18px"

};


const saveButton = {

  border: "none",

  background:
    "linear-gradient(135deg, #5c6bc0, #3949ab)",

  color: "#ffffff",

  padding: "12px 20px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

  boxShadow:
    "0 6px 15px rgba(63,81,181,0.20)"

};


const counter = {

  display: "flex",

  flexDirection: "column",

  alignItems: "center",

  background: "#eef4ff",

  padding: "8px 15px",

  borderRadius: "12px",

  color: "#3155a4"

};


const timeline = {

  display: "flex",

  flexDirection: "column",

  gap: "18px"

};


const timelineItem = {

  display: "flex",

  gap: "15px",

  alignItems: "flex-start"

};


const timelineDot = {

  minWidth: "38px",

  height: "38px",

  borderRadius: "50%",

  background:
    "linear-gradient(135deg, #5c6bc0, #42a5f5)",

  color: "#ffffff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontWeight: "800",

  fontSize: "13px"

};


const timelineCard = {

  flex: 1,

  background: "#f8fafc",

  border:
    "1px solid #e8edf3",

  borderRadius: "16px",

  padding: "18px"

};


const dateBadge = {

  display: "inline-block",

  background: "#eef4ff",

  color: "#3155a4",

  padding: "6px 10px",

  borderRadius: "8px",

  fontSize: "12px",

  fontWeight: "700",

  marginBottom: "15px"

};


const infoGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",

  gap: "12px"

};


const infoBlock = {

  background: "#ffffff",

  border:
    "1px solid #edf2f7",

  borderRadius: "12px",

  padding: "13px"

};


const infoBlockTitle = {

  display: "flex",

  alignItems: "center",

  gap: "6px",

  color: "#607d8b",

  fontSize: "12px",

  fontWeight: "800",

  marginBottom: "7px"

};


const infoBlockValue = {

  color: "#263238",

  fontSize: "13px",

  lineHeight: "1.5",

  whiteSpace: "pre-wrap",

  wordBreak: "break-word"

};


const emptyState = {

  textAlign: "center",

  padding: "45px 20px",

  background: "#f8fafc",

  borderRadius: "16px",

  border:
    "1px dashed #cbd5e1"

};


const emptyIcon = {

  fontSize: "45px",

  marginBottom: "10px"

};


const emptyTitle = {

  color: "#173b70",

  margin: "0 0 7px"

};


const emptyText = {

  color: "#718096",

  fontSize: "14px",

  margin: 0

};


const footer = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  marginTop: "25px",

  paddingTop: "18px",

  borderTop:
    "1px solid #e2e8f0",

  color: "#94a3b8",

  fontSize: "12px"

};


const footerLink = {

  border: "none",

  background: "transparent",

  color: "#3155a4",

  cursor: "pointer",

  fontWeight: "700"

};


const sessionList = {
  display: "flex",
  flexDirection: "column",
  gap: "16px"
};

const sessionCard = {
  border: "1px solid #dbe5f0",
  borderRadius: "18px",
  overflow: "hidden",
  background: "#ffffff",
  boxShadow: "0 5px 18px rgba(30,70,120,0.06)"
};

const sessionHeaderButton = {
  width: "100%",
  border: "none",
  background: "#f8fbff",
  padding: "18px 20px",
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "15px",
  cursor: "pointer",
  textAlign: "left"
};

const sessionHeaderLeft = { display: "flex", flexDirection: "column", gap: "5px" };
const sessionHeaderRight = { display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap", justifyContent: "flex-end" };
const sessionNumber = { color: "#173b70", fontSize: "17px", fontWeight: "800" };
const sessionMeta = { color: "#64748b", fontSize: "12px", textTransform: "capitalize" };
const statusFinalizada = { background: "#e9f8ef", color: "#218653", padding: "6px 10px", borderRadius: "999px", fontSize: "11px", fontWeight: "800" };
const statusActiva = { background: "#fff5e5", color: "#b7791f", padding: "6px 10px", borderRadius: "999px", fontSize: "11px", fontWeight: "800" };
const openButton = { color: "#3155a4", fontSize: "12px", fontWeight: "800" };
const sessionSummary = { padding: "11px 20px 15px", color: "#64748b", fontSize: "12px", borderTop: "1px solid #edf2f7" };
const sessionBody = { padding: "0 20px 20px", background: "#ffffff" };

const clinicalSection = { padding: "20px 0", borderTop: "1px solid #edf2f7" };
const clinicalSectionTitle = { margin: "0 0 14px", color: "#263238", fontSize: "16px" };
const detailGrid = { display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: "10px" };
const miniDetail = { background: "#f8fafc", border: "1px solid #edf2f7", borderRadius: "11px", padding: "11px" };
const miniLabel = { display: "block", color: "#94a3b8", fontSize: "10px", textTransform: "uppercase", fontWeight: "800", marginBottom: "4px" };
const miniValue = { color: "#334155", fontSize: "12px" };
const notesBox = { marginTop: "12px", background: "#f8fafc", border: "1px solid #edf2f7", borderRadius: "11px", padding: "13px", color: "#475569", fontSize: "13px", lineHeight: "1.6" };
const itemsGrid = { display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "10px" };
const resultCard = { display: "flex", flexDirection: "column", gap: "5px", background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: "12px", padding: "13px", color: "#475569", fontSize: "12px" };
const mediaList = { display: "flex", flexDirection: "column", gap: "9px" };
const mediaCard = { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px", background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: "12px", padding: "12px" };
const mediaLink = { textDecoration: "none", color: "#3155a4", fontSize: "12px", fontWeight: "800" };
const mutedText = { color: "#94a3b8", fontSize: "11px", marginTop: "4px" };
const transcriptList = { display: "flex", flexDirection: "column", gap: "10px" };
const transcriptCard = { background: "#f8fafc", border: "1px solid #dbe5f0", borderRadius: "12px", padding: "14px" };
const transcriptHeader = { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px", marginBottom: "10px", color: "#334155", fontSize: "13px" };
const transcriptBadge = { background: "#eef0ff", color: "#4f46b8", padding: "5px 8px", borderRadius: "999px", fontSize: "9px", fontWeight: "800", letterSpacing: "0.6px", whiteSpace: "nowrap" };
const transcriptText = { whiteSpace: "pre-wrap", wordBreak: "break-word", color: "#475569", fontSize: "13px", lineHeight: "1.65" };
const aiHistoryCard = { background: "#f8f9ff", border: "1px solid #dce2ff", borderRadius: "13px", padding: "14px" };
const aiHistoryTop = { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px" };
const inlineActions = { display: "flex", gap: "8px", flexWrap: "wrap" };
const secondaryButton = { border: "1px solid #cbd5e1", background: "#ffffff", color: "#3155a4", padding: "8px 11px", borderRadius: "9px", cursor: "pointer", fontWeight: "700", fontSize: "11px" };
const pdfButton = { border: "none", background: "#eef0ff", color: "#4f46b8", padding: "8px 11px", borderRadius: "9px", cursor: "pointer", fontWeight: "800", fontSize: "11px" };
const aiExpanded = { marginTop: "14px", background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: "11px", padding: "15px", whiteSpace: "pre-wrap", wordBreak: "break-word", color: "#334155", fontSize: "13px", lineHeight: "1.65" };
const emptyDetail = { background: "#f8fafc", border: "1px dashed #cbd5e1", borderRadius: "11px", padding: "13px", color: "#64748b", fontSize: "12px" };
const closureDate = { marginTop: "10px", color: "#94a3b8", fontSize: "11px", textAlign: "right" };


const loadingPage = {

  minHeight: "100vh",

  background:
    "linear-gradient(135deg, #eef6ff, #f8fbff)",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  padding: "30px"

};


const loadingCard = {

  background: "#ffffff",

  borderRadius: "20px",

  padding: "45px",

  textAlign: "center",

  boxShadow:
    "0 10px 30px rgba(30,70,120,0.10)"

};


const loadingIcon = {

  fontSize: "40px",

  marginBottom: "10px"

};


const loadingTitle = {

  margin: 0,

  color: "#173b70"

};


const loadingText = {

  color: "#718096",

  fontSize: "14px"

};