import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import axios from "axios";

import {
  useParams
} from "react-router-dom";


const ResponderEvaluacionEmpleado = () => {

  const { token } =
    useParams();


  const [evaluacion, setEvaluacion] =
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

  const preguntas =
    useMemo(
      () => {

        return Array.isArray(
          evaluacion?.preguntas
        )
          ? evaluacion.preguntas
          : [];

      },
      [evaluacion]
    );


  // ==================================================
  // CARGAR EVALUACIÓN PÚBLICA
  // ==================================================

  useEffect(
    () => {

      const cargarEvaluacion =
        async () => {

          try {

            setCargando(true);
            setError("");

            const respuesta =
              await axios.get(
                `/api/empleados/evaluacion-publica/${token}`
              );


            setEvaluacion(
              respuesta.data?.evaluacion ||
              null
            );


          } catch (err) {

            console.error(
              "❌ Error cargando evaluación pública:",
              err
            );


            setEvaluacion(null);


            setError(
              err.response?.data?.message ||
              "No fue posible abrir la evaluación."
            );


          } finally {

            setCargando(false);

          }

        };


      if (token) {
        cargarEvaluacion();
      }

    },
    [token]
  );


  // ==================================================
  // SELECCIONAR OPCIÓN
  // ==================================================

  const seleccionarOpcion =
    (
      idPregunta,
      idOpcion
    ) => {

      setRespuestas(
        prev => ({
          ...prev,

          [idPregunta]: {
            id_pregunta_rh:
              idPregunta,

            id_opcion_rh:
              idOpcion
          }
        })
      );

      setError("");
      setMensaje("");

    };


  // ==================================================
  // RESPUESTA ABIERTA
  // ==================================================

  const escribirRespuesta =
    (
      idPregunta,
      texto
    ) => {

      setRespuestas(
        prev => ({
          ...prev,

          [idPregunta]: {
            id_pregunta_rh:
              idPregunta,

            respuesta:
              texto
          }
        })
      );

      setError("");
      setMensaje("");

    };


  // ==================================================
  // OBTENER LISTA DE RESPUESTAS
  // ==================================================

  const obtenerListaRespuestas =
    () => {

      return Object.values(
        respuestas
      );

    };


  // ==================================================
  // VALIDAR QUE ESTÉ COMPLETA
  // ==================================================

  const validarCompleta =
    () => {

      if (
        preguntas.length === 0
      ) {
        return false;
      }


      for (
        const pregunta
        of preguntas
      ) {

        const respuesta =
          respuestas[
            pregunta.id_pregunta_rh
          ];


        if (!respuesta) {
          return false;
        }


        if (
          pregunta.tipo_respuesta ===
          "abierta"
        ) {

          if (
            !String(
              respuesta.respuesta ||
              ""
            ).trim()
          ) {
            return false;
          }

        }


        if (
          pregunta.tipo_respuesta ===
            "opcion" ||
          pregunta.tipo_respuesta ===
            "escala"
        ) {

          if (
            !respuesta.id_opcion_rh
          ) {
            return false;
          }

        }

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
          `/api/empleados/evaluacion-publica/${token}/respuestas`,
          {
            respuestas:
              lista
          }
        );


        if (
          mostrarMensaje
        ) {

          setMensaje(
            "Tus respuestas fueron guardadas correctamente."
          );

        }


        return true;


      } catch (err) {

        console.error(
          "❌ Error guardando respuestas:",
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
  // FINALIZAR EVALUACIÓN
  // ==================================================

  const finalizarEvaluacion =
    async () => {

      if (
        !validarCompleta()
      ) {

        setError(
          "Debes responder todas las preguntas antes de finalizar."
        );

        return;
      }


      const confirmar =
        window.confirm(
          "¿Deseas finalizar la evaluación? Después de finalizar ya no podrás modificar tus respuestas."
        );


      if (!confirmar) {
        return;
      }


      try {

        setFinalizando(true);
        setError("");
        setMensaje("");


        // ==================================================
        // PRIMERO GUARDAR TODAS LAS RESPUESTAS
        // ==================================================

        const guardado =
          await guardarRespuestas(
            false
          );


        if (!guardado) {
          return;
        }


        // ==================================================
        // FINALIZAR
        // ==================================================

        const respuesta =
          await axios.post(
            `/api/empleados/evaluacion-publica/${token}/finalizar`
          );


        setResultado(
          respuesta.data?.resultado ||
          null
        );


        setCompletada(
          true
        );


      } catch (err) {

        console.error(
          "❌ Error finalizando evaluación:",
          err
        );


        setError(
          err.response?.data?.message ||
          "No fue posible finalizar la evaluación."
        );


      } finally {

        setFinalizando(false);

      }

    };


  // ==================================================
  // PROGRESO
  // ==================================================

  const respondidas =
    preguntas.filter(
      pregunta => {

        const respuesta =
          respuestas[
            pregunta.id_pregunta_rh
          ];


        if (!respuesta) {
          return false;
        }


        if (
          pregunta.tipo_respuesta ===
          "abierta"
        ) {

          return Boolean(
            String(
              respuesta.respuesta ||
              ""
            ).trim()
          );

        }


        return Boolean(
          respuesta.id_opcion_rh
        );

      }
    ).length;


  const porcentaje =
    preguntas.length
      ? Math.round(
          (
            respondidas /
            preguntas.length
          ) * 100
        )
      : 0;


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
            Cargando evaluación...
          </p>

        </div>

      </div>

    );

  }


  // ==================================================
  // ERROR SIN EVALUACIÓN
  // ==================================================

  if (
    error &&
    !evaluacion
  ) {

    return (

      <div style={styles.page}>

        <div style={styles.centerCard}>

          <div style={styles.bigIcon}>
            ⚠️
          </div>

          <h2>
            No fue posible abrir la evaluación
          </h2>

          <p style={styles.muted}>
            {error}
          </p>

        </div>

      </div>

    );

  }


  // ==================================================
  // EVALUACIÓN COMPLETADA
  // ==================================================

  if (completada) {

    return (

      <div style={styles.page}>

        <div style={styles.centerCard}>

          <div style={styles.bigIcon}>
            ✅
          </div>


          <h1>
            Evaluación completada
          </h1>


          <p style={styles.muted}>
            Tus respuestas fueron registradas
            correctamente.
          </p>


          <div style={styles.completeBox}>

            <strong>
              {
                evaluacion?.prueba?.nombre ||
                "Evaluación RH"
              }
            </strong>


            <p style={styles.completeText}>
              Recursos Humanos podrá consultar
              los resultados de esta evaluación
              dentro de tu expediente laboral.
            </p>

          </div>


          {resultado?.puntaje_total !==
            undefined && (

            <div style={styles.processedBox}>

              <strong>
                Evaluación procesada
              </strong>

              <p>
                La evaluación fue registrada
                correctamente en MirrorSoul.
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


        {/* ==========================================
            ENCABEZADO
        ========================================== */}

        <div style={styles.headerCard}>

          <div style={styles.brand}>
            🧠 MirrorSoul
          </div>


          <h1 style={styles.title}>
            {
              evaluacion?.prueba?.nombre ||
              "Evaluación"
            }
          </h1>


          {evaluacion?.prueba?.descripcion && (

            <p style={styles.description}>
              {
                evaluacion.prueba.descripcion
              }
            </p>

          )}


          {/* DATOS */}

          <div style={styles.infoGrid}>

            <div style={styles.infoBox}>

              <span style={styles.infoLabel}>
                Empleado
              </span>

              <strong>
                {
                  evaluacion?.empleado?.nombre ||
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
                  evaluacion?.empleado?.id_mirror ||
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
                  evaluacion?.empleado?.puesto ||
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
                  evaluacion?.empleado?.departamento ||
                  "No especificado"
                }
              </strong>

            </div>

          </div>


          {evaluacion?.motivo && (

            <div style={styles.reasonBox}>

              <span style={styles.infoLabel}>
                Motivo de la evaluación
              </span>

              <p style={styles.reasonText}>
                {
                  evaluacion.motivo
                }
              </p>

            </div>

          )}


          <div style={styles.instructions}>

            <strong>
              Instrucciones
            </strong>

            <p style={styles.instructionsText}>
              Lee cada pregunta con atención y
              selecciona la respuesta que mejor
              represente tu situación. Responde
              de forma sincera y evita dejar
              preguntas sin contestar.
            </p>

          </div>

        </div>


        {/* ==========================================
            PROGRESO
        ========================================== */}

        <div style={styles.progressCard}>

          <div style={styles.progressTop}>

            <strong>
              Progreso
            </strong>

            <span>
              {respondidas} de{" "}
              {preguntas.length}
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


        {/* ==========================================
            MENSAJES
        ========================================== */}

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


        {/* ==========================================
            SIN PREGUNTAS
        ========================================== */}

        {preguntas.length === 0 ? (

          <div style={styles.questionCard}>

            <div style={styles.bigIcon}>
              📋
            </div>

            <h3>
              Esta evaluación no contiene
              preguntas disponibles.
            </h3>

          </div>

        ) : (

          preguntas.map(
            (
              pregunta,
              indice
            ) => {

              const respuestaActual =
                respuestas[
                  pregunta.id_pregunta_rh
                ];


              return (

                <div
                  key={
                    pregunta.id_pregunta_rh
                  }
                  style={styles.questionCard}
                >

                  <div style={styles.questionNumber}>
                    Pregunta {indice + 1}
                  </div>


                  <h3 style={styles.questionText}>
                    {
                      pregunta.texto_pregunta
                    }
                  </h3>


                  {/* ==================================
                      OPCIÓN / ESCALA
                  ================================== */}

                  {(
                    pregunta.tipo_respuesta ===
                      "opcion" ||
                    pregunta.tipo_respuesta ===
                      "escala"
                  ) && (

                    <div style={styles.options}>

                      {Array.isArray(
                        pregunta.opciones
                      ) &&
                        pregunta.opciones.map(
                          opcion => {

                            const seleccionada =
                              Number(
                                respuestaActual
                                  ?.id_opcion_rh
                              ) ===
                              Number(
                                opcion.id_opcion_rh
                              );


                            return (

                              <label
                                key={
                                  opcion.id_opcion_rh
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
                                    `pregunta-${pregunta.id_pregunta_rh}`
                                  }
                                  checked={
                                    seleccionada
                                  }
                                  onChange={() =>
                                    seleccionarOpcion(
                                      pregunta.id_pregunta_rh,
                                      opcion.id_opcion_rh
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

                  )}


                  {/* ==================================
                      RESPUESTA ABIERTA
                  ================================== */}

                  {pregunta.tipo_respuesta ===
                    "abierta" && (

                    <textarea
                      style={styles.textarea}
                      rows={5}
                      placeholder="Escribe tu respuesta..."
                      value={
                        respuestaActual
                          ?.respuesta ||
                        ""
                      }
                      onChange={
                        e =>
                          escribirRespuesta(
                            pregunta.id_pregunta_rh,
                            e.target.value
                          )
                      }
                    />

                  )}

                </div>

              );

            }
          )

        )}


        {/* ==========================================
            ACCIONES
        ========================================== */}

        {preguntas.length > 0 && (

          <div style={styles.actionsCard}>

            <div style={styles.actionsInfo}>

              <strong>
                {respondidas}/{preguntas.length}
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
                  guardarRespuestas(
                    true
                  )
                }
              >
                {
                  guardando
                    ? "Guardando..."
                    : "💾 Guardar respuestas"
                }
              </button>


              <button
                type="button"
                style={styles.finishButton}
                disabled={
                  guardando ||
                  finalizando
                }
                onClick={
                  finalizarEvaluacion
                }
              >
                {
                  finalizando
                    ? "Finalizando..."
                    : "✅ Finalizar evaluación"
                }
              </button>

            </div>

          </div>

        )}


        {/* ==========================================
            AVISO
        ========================================== */}

        <div style={styles.footerNotice}>

          <strong>
            Privacidad y uso
          </strong>

          <p style={styles.footerText}>
            Esta evaluación forma parte del
            seguimiento laboral y preventivo.
            Los resultados serán consultados por
            el área autorizada de Recursos
            Humanos y no representan por sí solos
            un diagnóstico clínico.
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
    marginBottom: "14px"
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
    cursor: "pointer",
    transition:
      "all .15s ease"
  },

  optionSelected: {
    background: "#eff6ff",
    border: "2px solid #2563eb"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "12px",
    marginTop: "15px",
    resize: "vertical",
    fontFamily: "inherit",
    fontSize: "15px"
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


export default ResponderEvaluacionEmpleado;