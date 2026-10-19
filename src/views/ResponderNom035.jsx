import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import axios from "axios";
import { useParams } from "react-router-dom";


const ResponderNom035 = () => {

  const { token } = useParams();

  const [aplicacion, setAplicacion] =
    useState(null);

  const [respuestas, setRespuestas] =
    useState({});

  const [cargando, setCargando] =
    useState(true);

  const [guardando, setGuardando] =
    useState(false);

  const [finalizando, setFinalizando] =
    useState(false);

  const [completada, setCompletada] =
    useState(false);

  const [resultado, setResultado] =
    useState(null);

  const [error, setError] =
    useState("");

  const [mensaje, setMensaje] =
    useState("");


  // ==================================================
  // PREGUNTAS
  // ==================================================

  const preguntas = useMemo(
    () =>
      Array.isArray(
        aplicacion?.preguntas
      )
        ? aplicacion.preguntas
        : [],
    [aplicacion]
  );


  // ==================================================
  // GUÍA I
  // ==================================================

  const esGuiaI =
    String(
      aplicacion?.cuestionario?.guia ||
      ""
    ) === "I";


  const preguntasSeccionI =
    useMemo(
      () => {

        if (!esGuiaI) {
          return [];
        }

        return preguntas.filter(
          pregunta => {

            const orden =
              Number(
                pregunta.orden
              );

            return (
              orden >= 1 &&
              orden <= 6
            );
          }
        );

      },
      [
        preguntas,
        esGuiaI
      ]
    );


  const seccionICompleta =
    esGuiaI &&
    preguntasSeccionI.length === 6 &&
    preguntasSeccionI.every(
      pregunta =>
        Boolean(
          respuestas[
            pregunta.id_pregunta
          ]?.id_opcion
        )
    );


  const algunaRespuestaSiSeccionI =
    esGuiaI &&
    preguntasSeccionI.some(
      pregunta => {

        const respuesta =
          respuestas[
            pregunta.id_pregunta
          ];

        if (
          !respuesta?.id_opcion
        ) {
          return false;
        }

        const opcion =
          pregunta.opciones?.find(
            item =>
              Number(
                item.id_opcion
              ) ===
              Number(
                respuesta.id_opcion
              )
          );

        return (
          Number(
            opcion?.valor
          ) === 1
        );
      }
    );


  const guiaITerminaEnSeccionI =
    esGuiaI &&
    seccionICompleta &&
    !algunaRespuestaSiSeccionI;


  // ==================================================
  // PREGUNTAS VISIBLES
  // ==================================================

  const preguntasVisibles =
    useMemo(
      () => {

        if (!esGuiaI) {
          return preguntas;
        }

        if (
          !seccionICompleta ||
          guiaITerminaEnSeccionI
        ) {
          return preguntas.filter(
            pregunta => {

              const orden =
                Number(
                  pregunta.orden
                );

              return (
                orden >= 1 &&
                orden <= 6
              );
            }
          );
        }

        return preguntas;

      },
      [
        preguntas,
        esGuiaI,
        seccionICompleta,
        guiaITerminaEnSeccionI
      ]
    );


  // ==================================================
  // CARGAR
  // ==================================================

  useEffect(
    () => {

      const cargarAplicacion =
        async () => {

          try {
            setCargando(true);
            setError("");

            const respuesta =
              await axios.get(
                `/api/empleados/nom035-publica/${token}`
              );

            const datos =
              respuesta.data?.aplicacion ||
              null;

            setAplicacion(datos);


            // ==========================================
            // RECUPERAR RESPUESTAS GUARDADAS
            // ==========================================

            if (
              Array.isArray(
                datos?.preguntas
              )
            ) {
              const recuperadas = {};

              datos.preguntas.forEach(
                pregunta => {

                  if (
                    pregunta.respuesta_actual
                      ?.id_opcion
                  ) {
                    recuperadas[
                      pregunta.id_pregunta
                    ] = {
                      id_pregunta:
                        pregunta.id_pregunta,

                      id_opcion:
                        pregunta
                          .respuesta_actual
                          .id_opcion
                    };
                  }
                }
              );

              setRespuestas(
                recuperadas
              );
            }

          } catch (err) {
            console.error(
              "❌ Error cargando NOM-035 pública:",
              err
            );

            setAplicacion(null);

            setError(
              err.response?.data?.message ||
              "No fue posible abrir el cuestionario NOM-035."
            );

          } finally {
            setCargando(false);
          }
        };

      if (token) {
        cargarAplicacion();
      }

    },
    [token]
  );


  // ==================================================
  // SELECCIONAR RESPUESTA
  // ==================================================

  const seleccionarRespuesta =
    (
      idPregunta,
      idOpcion
    ) => {

      setRespuestas(
        prev => ({
          ...prev,

          [idPregunta]: {
            id_pregunta:
              idPregunta,

            id_opcion:
              idOpcion
          }
        })
      );

      setError("");
      setMensaje("");
    };


  // ==================================================
  // LISTA DE RESPUESTAS
  // ==================================================

  const obtenerListaRespuestas =
    () => {

      const idsVisibles =
        new Set(
          preguntasVisibles.map(
            pregunta =>
              Number(
                pregunta.id_pregunta
              )
          )
        );

      return Object.values(
        respuestas
      ).filter(
        respuesta =>
          idsVisibles.has(
            Number(
              respuesta.id_pregunta
            )
          )
      );
    };


  // ==================================================
  // VALIDAR COMPLETA
  // ==================================================

  const validarCompleta =
    () => {

      if (
        preguntasVisibles.length === 0
      ) {
        return false;
      }

      for (
        const pregunta
        of preguntasVisibles
      ) {
        const respuesta =
          respuestas[
            pregunta.id_pregunta
          ];

        if (
          !respuesta ||
          !respuesta.id_opcion
        ) {
          return false;
        }
      }

      if (
        esGuiaI &&
        algunaRespuestaSiSeccionI
      ) {
        return preguntas.every(
          pregunta =>
            Boolean(
              respuestas[
                pregunta.id_pregunta
              ]?.id_opcion
            )
        );
      }

      return true;
    };


  // ==================================================
  // GUARDAR RESPUESTAS
  // ==================================================

  const guardarRespuestas =
    async (
      mostrarMensaje = true
    ) => {

      const lista =
        obtenerListaRespuestas();

      if (!lista.length) {
        setError(
          "Debes responder al menos una pregunta."
        );

        return false;
      }

      try {
        setGuardando(true);
        setError("");

        await axios.post(
          `/api/empleados/nom035-publica/${token}/respuestas`,
          {
            respuestas: lista
          }
        );

        if (mostrarMensaje) {
          setMensaje(
            "Tus respuestas fueron guardadas correctamente."
          );
        }

        return true;

      } catch (err) {
        console.error(
          "❌ Error guardando respuestas NOM-035:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible guardar las respuestas."
        );

        return false;

      } finally {
        setGuardando(false);
      }
    };


  // ==================================================
  // FINALIZAR
  // ==================================================

  const finalizarAplicacion =
    async () => {

      if (!validarCompleta()) {
        setError(
          esGuiaI &&
          algunaRespuestaSiSeccionI
            ? "Debes responder las secciones II, III y IV antes de finalizar."
            : "Debes responder todas las preguntas requeridas antes de finalizar."
        );

        return;
      }

      const confirmar =
        window.confirm(
          "¿Deseas finalizar el cuestionario? Después de finalizar ya no podrás modificar tus respuestas."
        );

      if (!confirmar) {
        return;
      }

      try {
        setFinalizando(true);
        setError("");
        setMensaje("");

        const guardado =
          await guardarRespuestas(
            false
          );

        if (!guardado) {
          return;
        }

        const respuesta =
          await axios.post(
            `/api/empleados/nom035-publica/${token}/finalizar`
          );

        setResultado(
          respuesta.data?.resultado ||
          null
        );

        setCompletada(true);

      } catch (err) {
        console.error(
          "❌ Error finalizando NOM-035:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible finalizar el cuestionario."
        );

      } finally {
        setFinalizando(false);
      }
    };


  // ==================================================
  // PROGRESO
  // ==================================================

  const respondidas =
    preguntasVisibles.filter(
      pregunta =>
        Boolean(
          respuestas[
            pregunta.id_pregunta
          ]?.id_opcion
        )
    ).length;


  const porcentaje =
    preguntasVisibles.length
      ? Math.round(
          (
            respondidas /
            preguntasVisibles.length
          ) * 100
        )
      : 0;


  // ==================================================
  // SECCIONES
  // ==================================================

  const secciones =
    useMemo(
      () => {

        const grupos = [];

        for (
          const pregunta
          of preguntasVisibles
        ) {

          const nombreSeccion =
            pregunta.seccion ||
            "Cuestionario";

          let grupo =
            grupos.find(
              item =>
                item.nombre ===
                nombreSeccion
            );

          if (!grupo) {
            grupo = {
              nombre:
                nombreSeccion,
              preguntas: []
            };

            grupos.push(
              grupo
            );
          }

          grupo.preguntas.push(
            pregunta
          );
        }

        return grupos;

      },
      [preguntasVisibles]
    );


  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.centerCard}>
          <div style={styles.logo}>
            🧠
          </div>

          <h2>
            MirrorSoul
          </h2>

          <p style={styles.muted}>
            Cargando cuestionario NOM-035...
          </p>
        </div>
      </div>
    );
  }


  // ==================================================
  // ERROR
  // ==================================================

  if (
    error &&
    !aplicacion
  ) {
    return (
      <div style={styles.page}>
        <div style={styles.centerCard}>
          <div style={styles.bigIcon}>
            ⚠️
          </div>

          <h2>
            No fue posible abrir el cuestionario
          </h2>

          <p style={styles.muted}>
            {error}
          </p>
        </div>
      </div>
    );
  }


  // ==================================================
  // COMPLETADA
  // ==================================================

  if (completada) {
    return (
      <div style={styles.page}>
        <div style={styles.centerCard}>
          <div style={styles.bigIcon}>
            ✅
          </div>

          <h1>
            Cuestionario completado
          </h1>

          <p style={styles.muted}>
            Tus respuestas fueron registradas
            correctamente.
          </p>

          <div style={styles.completeBox}>
            <strong>
              {
                aplicacion?.cuestionario
                  ?.nombre ||
                "NOM-035"
              }
            </strong>

            <p style={styles.completeText}>
              La aplicación quedó guardada dentro
              de tu expediente laboral preventivo.
            </p>
          </div>

          {resultado?.guia === "I" && (
            <div style={styles.processedBox}>
              <strong>
                Guía I procesada
              </strong>

              <p style={styles.completeText}>
                El cuestionario fue procesado
                conforme a la lógica configurada
                para la Guía I.
              </p>
            </div>
          )}

          <p style={styles.smallText}>
            Ya puedes cerrar esta ventana.
          </p>
        </div>
      </div>
    );
  }


  return (
    <div style={styles.page}>

      <div style={styles.container}>

        {/* ENCABEZADO */}

        <div style={styles.headerCard}>

          <div style={styles.brand}>
            🧠 MirrorSoul
          </div>

          <div style={styles.guideBadge}>
            Guía{" "}
            {
              aplicacion?.cuestionario
                ?.guia ||
              "-"
            }
          </div>

          <h1 style={styles.title}>
            {
              aplicacion?.cuestionario
                ?.nombre ||
              "Cuestionario NOM-035"
            }
          </h1>

          {aplicacion?.cuestionario
            ?.descripcion && (
            <p style={styles.description}>
              {
                aplicacion.cuestionario
                  .descripcion
              }
            </p>
          )}

          <div style={styles.infoGrid}>

            <div style={styles.infoBox}>
              <span style={styles.infoLabel}>
                Empleado
              </span>

              <strong>
                {
                  aplicacion?.empleado
                    ?.nombre ||
                  "No disponible"
                }
              </strong>
            </div>

            <div style={styles.infoBox}>
              <span style={styles.infoLabel}>
                ID MirrorSoul
              </span>

              <strong>
                {
                  aplicacion?.empleado
                    ?.id_mirror ||
                  "No disponible"
                }
              </strong>
            </div>

            <div style={styles.infoBox}>
              <span style={styles.infoLabel}>
                Puesto
              </span>

              <strong>
                {
                  aplicacion?.empleado
                    ?.puesto ||
                  "No especificado"
                }
              </strong>
            </div>

            <div style={styles.infoBox}>
              <span style={styles.infoLabel}>
                Departamento
              </span>

              <strong>
                {
                  aplicacion?.empleado
                    ?.departamento ||
                  "No especificado"
                }
              </strong>
            </div>

          </div>


          {aplicacion?.motivo && (
            <div style={styles.reasonBox}>
              <span style={styles.infoLabel}>
                Motivo de aplicación
              </span>

              <p style={styles.reasonText}>
                {aplicacion.motivo}
              </p>
            </div>
          )}


          <div style={styles.instructions}>
            <strong>
              Instrucciones
            </strong>

            <p style={styles.instructionsText}>
              Lee cuidadosamente cada pregunta y
              selecciona la respuesta que corresponda.
              Responde las preguntas mostradas antes
              de finalizar.
            </p>
          </div>

        </div>


        {/* PROGRESO */}

        <div style={styles.progressCard}>

          <div style={styles.progressTop}>
            <strong>
              Progreso
            </strong>

            <span>
              {respondidas} de{" "}
              {preguntasVisibles.length}
            </span>
          </div>

          <div style={styles.progressTrack}>
            <div
              style={{
                ...styles.progressBar,
                width:
                  `${porcentaje}%`
              }}
            />
          </div>

          <div style={styles.progressPercent}>
            {porcentaje}% completado
          </div>

        </div>


        {/* MENSAJES */}

        {mensaje && (
          <div style={styles.success}>
            ✅ {mensaje}
          </div>
        )}

        {error && (
          <div style={styles.error}>
            ❌ {error}
          </div>
        )}


        {/* GUÍA I */}

        {esGuiaI &&
          seccionICompleta &&
          guiaITerminaEnSeccionI && (

          <div style={styles.guideFinishedNotice}>
            <strong>
              ✅ Sección I completada
            </strong>

            <p style={styles.guideFinishedText}>
              Todas las respuestas de la Sección I
              fueron "No". No es necesario responder
              las demás secciones. Puedes finalizar
              el cuestionario.
            </p>
          </div>
        )}


        {esGuiaI &&
          seccionICompleta &&
          algunaRespuestaSiSeccionI && (

          <div style={styles.continueNotice}>
            <strong>
              📋 Continúa con el cuestionario
            </strong>

            <p style={styles.guideFinishedText}>
              Al existir al menos una respuesta "Sí"
              en la Sección I, debes responder también
              las secciones II, III y IV.
            </p>
          </div>
        )}


        {/* PREGUNTAS */}

        {preguntasVisibles.length === 0 ? (

          <div style={styles.questionCard}>
            <div style={styles.bigIcon}>
              📋
            </div>

            <h3>
              Este cuestionario todavía no tiene
              preguntas disponibles.
            </h3>
          </div>

        ) : (

          secciones.map(
            (
              seccion,
              indiceSeccion
            ) => (

              <div
                key={
                  `${seccion.nombre}-${indiceSeccion}`
                }
                style={styles.sectionBlock}
              >

                <div style={styles.sectionHeader}>
                  <span style={styles.sectionNumber}>
                    Sección {indiceSeccion + 1}
                  </span>

                  <h2 style={styles.sectionTitle}>
                    {seccion.nombre}
                  </h2>
                </div>


                {seccion.preguntas.map(
                  (
                    pregunta,
                    indicePregunta
                  ) => {

                    const respuestaActual =
                      respuestas[
                        pregunta.id_pregunta
                      ];

                    return (
                      <div
                        key={
                          pregunta.id_pregunta
                        }
                        style={styles.questionCard}
                      >

                        <div style={styles.questionNumber}>
                          {
                            pregunta.numero
                              ? `Pregunta ${pregunta.numero}`
                              : `Pregunta ${indicePregunta + 1}`
                          }
                        </div>

                        <h3 style={styles.questionText}>
                          {
                            pregunta.texto_pregunta
                          }
                        </h3>

                        {pregunta.dominio && (
                          <div style={styles.questionMeta}>
                            Dominio:{" "}
                            {pregunta.dominio}
                          </div>
                        )}

                        <div style={styles.options}>

                          {Array.isArray(
                            pregunta.opciones
                          ) &&
                            pregunta.opciones.map(
                              opcion => {

                                const seleccionada =
                                  Number(
                                    respuestaActual
                                      ?.id_opcion
                                  ) ===
                                  Number(
                                    opcion.id_opcion
                                  );

                                return (
                                  <label
                                    key={
                                      opcion.id_opcion
                                    }
                                    style={{
                                      ...styles.option,

                                      ...(seleccionada
                                        ? styles.optionSelected
                                        : {})
                                    }}
                                  >
                                    <input
                                      type="radio"
                                      name={
                                        `pregunta-${pregunta.id_pregunta}`
                                      }
                                      checked={
                                        seleccionada
                                      }
                                      onChange={() =>
                                        seleccionarRespuesta(
                                          pregunta.id_pregunta,
                                          opcion.id_opcion
                                        )
                                      }
                                    />

                                    <span>
                                      {
                                        opcion.texto_opcion
                                      }
                                    </span>
                                  </label>
                                );
                              }
                            )}

                        </div>

                      </div>
                    );
                  }
                )}

              </div>
            )
          )
        )}


        {/* ACCIONES */}

        {preguntasVisibles.length > 0 && (

          <div style={styles.actionsCard}>

            <div style={styles.actionsInfo}>
              <strong>
                {respondidas}/
                {preguntasVisibles.length}
              </strong>

              <span>
                preguntas respondidas
              </span>
            </div>


            <div style={styles.actions}>

              <button
                type="button"
                style={styles.saveButton}
                disabled={
                  guardando ||
                  finalizando
                }
                onClick={() =>
                  guardarRespuestas(true)
                }
              >
                {
                  guardando
                    ? "Guardando..."
                    : "💾 Guardar avance"
                }
              </button>


              <button
                type="button"
                style={styles.finishButton}
                disabled={
                  guardando ||
                  finalizando ||
                  !validarCompleta()
                }
                onClick={
                  finalizarAplicacion
                }
              >
                {
                  finalizando
                    ? "Finalizando..."
                    : guiaITerminaEnSeccionI
                    ? "✅ Finalizar Guía I"
                    : "✅ Finalizar cuestionario"
                }
              </button>

            </div>

          </div>
        )}


        {/* PRIVACIDAD */}

        <div style={styles.footerNotice}>
          <strong>
            Privacidad y uso
          </strong>

          <p style={styles.footerText}>
            La información de esta aplicación forma
            parte del seguimiento preventivo y laboral
            autorizado. No constituye por sí misma un
            diagnóstico clínico y no se incorpora al
            expediente psicológico del empleado.
          </p>
        </div>

      </div>

    </div>
  );
};


// ==================================================
// ESTILOS
// ==================================================

const styles = {

  page: {
    minHeight: "100vh",
    background: "#f5f7fa",
    padding: "30px 18px"
  },

  container: {
    maxWidth: "850px",
    margin: "0 auto"
  },

  centerCard: {
    maxWidth: "620px",
    margin: "60px auto",
    background: "#ffffff",
    borderRadius: "18px",
    padding: "35px",
    textAlign: "center",
    boxShadow:
      "0 5px 22px rgba(0,0,0,.06)"
  },

  logo: {
    fontSize: "42px"
  },

  bigIcon: {
    fontSize: "50px",
    marginBottom: "8px"
  },

  muted: {
    color: "#667085",
    lineHeight: 1.5
  },

  headerCard: {
    background: "#ffffff",
    borderRadius: "18px",
    padding: "28px",
    marginBottom: "18px",
    textAlign: "center",
    boxShadow:
      "0 4px 20px rgba(0,0,0,.05)"
  },

  brand: {
    fontSize: "20px",
    fontWeight: "800",
    marginBottom: "12px"
  },

  guideBadge: {
    display: "inline-block",
    background: "#ede9fe",
    color: "#5b21b6",
    borderRadius: "20px",
    padding: "6px 11px",
    fontSize: "13px",
    fontWeight: "800",
    marginBottom: "12px"
  },

  title: {
    margin: "0 0 9px"
  },

  description: {
    color: "#667085",
    lineHeight: 1.55,
    maxWidth: "650px",
    margin: "0 auto"
  },

  infoGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(150px, 1fr))",
    gap: "11px",
    marginTop: "24px"
  },

  infoBox: {
    background: "#f8fafc",
    borderRadius: "10px",
    padding: "13px",
    display: "flex",
    flexDirection: "column",
    gap: "5px"
  },

  infoLabel: {
    color: "#667085",
    fontSize: "12px"
  },

  reasonBox: {
    background: "#f8fafc",
    borderRadius: "10px",
    padding: "13px",
    marginTop: "14px"
  },

  reasonText: {
    margin: "5px 0 0",
    color: "#344054"
  },

  instructions: {
    marginTop: "20px",
    padding: "15px",
    borderRadius: "10px",
    background: "#eff6ff",
    color: "#1e3a8a",
    textAlign: "left"
  },

  instructionsText: {
    margin: "6px 0 0",
    lineHeight: 1.5
  },

  progressCard: {
    background: "#ffffff",
    borderRadius: "14px",
    padding: "17px",
    marginBottom: "18px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.04)"
  },

  progressTop: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: "9px"
  },

  progressTrack: {
    height: "10px",
    background: "#e4e7ec",
    borderRadius: "20px",
    overflow: "hidden"
  },

  progressBar: {
    height: "100%",
    background: "#2563eb",
    transition:
      "width .25s ease"
  },

  progressPercent: {
    marginTop: "7px",
    color: "#667085",
    fontSize: "12px",
    textAlign: "right"
  },

  success: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    padding: "13px",
    borderRadius: "10px",
    marginBottom: "16px"
  },

  error: {
    background: "#fef3f2",
    border: "1px solid #fecdca",
    padding: "13px",
    borderRadius: "10px",
    marginBottom: "16px"
  },

  guideFinishedNotice: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "18px",
    color: "#067647"
  },

  continueNotice: {
    background: "#fff7ed",
    border: "1px solid #fed7aa",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "18px",
    color: "#9a3412"
  },

  guideFinishedText: {
    margin: "6px 0 0",
    lineHeight: 1.5
  },

  sectionBlock: {
    marginBottom: "24px"
  },

  sectionHeader: {
    marginBottom: "12px"
  },

  sectionNumber: {
    color: "#667085",
    fontSize: "13px",
    fontWeight: "700"
  },

  sectionTitle: {
    margin: "4px 0 0",
    fontSize: "21px"
  },

  questionCard: {
    background: "#ffffff",
    borderRadius: "15px",
    padding: "23px",
    marginBottom: "15px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.04)"
  },

  questionNumber: {
    color: "#667085",
    fontSize: "13px",
    fontWeight: "700",
    marginBottom: "8px"
  },

  questionText: {
    margin: 0,
    lineHeight: 1.5
  },

  questionMeta: {
    marginTop: "7px",
    color: "#667085",
    fontSize: "12px"
  },

  options: {
    display: "flex",
    flexDirection: "column",
    gap: "10px",
    marginTop: "18px"
  },

  option: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    border: "1px solid #e4e7ec",
    borderRadius: "10px",
    padding: "13px",
    cursor: "pointer"
  },

  optionSelected: {
    background: "#eff6ff",
    border: "2px solid #2563eb"
  },

  actionsCard: {
    background: "#ffffff",
    borderRadius: "15px",
    padding: "18px",
    marginTop: "18px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    flexWrap: "wrap",
    gap: "15px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)"
  },

  actionsInfo: {
    display: "flex",
    flexDirection: "column",
    gap: "3px",
    color: "#667085"
  },

  actions: {
    display: "flex",
    flexWrap: "wrap",
    gap: "10px"
  },

  saveButton: {
    border: "1px solid #d0d5dd",
    background: "#ffffff",
    borderRadius: "10px",
    padding: "11px 16px",
    cursor: "pointer",
    fontWeight: "700"
  },

  finishButton: {
    border: "none",
    background: "#2563eb",
    color: "#ffffff",
    borderRadius: "10px",
    padding: "11px 16px",
    cursor: "pointer",
    fontWeight: "700"
  },

  completeBox: {
    marginTop: "24px",
    padding: "18px",
    background: "#f8fafc",
    borderRadius: "12px"
  },

  completeText: {
    color: "#667085",
    marginBottom: 0,
    lineHeight: 1.5
  },

  processedBox: {
    marginTop: "15px",
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    borderRadius: "10px",
    padding: "14px"
  },

  smallText: {
    color: "#667085",
    fontSize: "14px",
    marginTop: "20px"
  },

  footerNotice: {
    marginTop: "18px",
    padding: "15px",
    borderRadius: "10px",
    background: "#ffffff",
    color: "#475467",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.04)"
  },

  footerText: {
    margin: "6px 0 0",
    fontSize: "13px",
    lineHeight: 1.5
  }
};


export default ResponderNom035;