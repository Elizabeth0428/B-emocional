// src/views/PruebasView.jsx

import React, { useEffect, useState } from "react";
import axios from "axios";
import { getToken } from "../services/AuthService";

const API_URL = "https://reflejoyalma.com";

export default function PruebasView({
  onBack,
  idPaciente,
  idSesion = null,
  token: tokenProp
}) {
  const [pruebas, setPruebas] = useState([]);
  const [pruebasHabilitadas, setPruebasHabilitadas] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingHabilitar, setLoadingHabilitar] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [enlaceGenerado, setEnlaceGenerado] = useState("");
  const [pruebaGenerada, setPruebaGenerada] = useState(null);

  const token = tokenProp || getToken();

  /* ==================================================
     NORMALIZAR ID DE SESIÓN
  ================================================== */

  const idSesionActual =
    idSesion !== null &&
    idSesion !== undefined &&
    idSesion !== ""
      ? Number(idSesion)
      : null;

  /* ==================================================
     CARGAR PRUEBAS
  ================================================== */

  const cargarPruebas = async () => {
    if (!idPaciente) {
      setErrorMsg("⚠️ Primero selecciona un paciente.");
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setErrorMsg("");

      const resPruebas = await axios.get(
        `${API_URL}/api/evaluation/pruebas`,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      console.log(
        "🧪 Pruebas recibidas:",
        resPruebas.data
      );

      setPruebas(
        Array.isArray(resPruebas.data)
          ? resPruebas.data
          : []
      );

      const resHabilitadas = await axios.get(
        `${API_URL}/api/evaluation/pruebas/habilitadas/${idPaciente}`,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      console.log(
        "🔗 Pruebas habilitadas:",
        resHabilitadas.data
      );

      setPruebasHabilitadas(
        Array.isArray(resHabilitadas.data)
          ? resHabilitadas.data
          : []
      );
    } catch (error) {
      console.error(
        "❌ Error cargando pruebas:",
        error
      );

      if (
        error?.response?.status === 401 ||
        error?.response?.status === 403
      ) {
        setErrorMsg(
          "❌ Tu sesión expiró. Inicia sesión nuevamente."
        );
      } else {
        setErrorMsg(
          error?.response?.data?.message ||
          "❌ No se pudieron cargar las pruebas."
        );
      }

      setPruebas([]);
    } finally {
      setLoading(false);
    }
  };

  /* ==================================================
     CARGAR AL ENTRAR
  ================================================== */

  useEffect(() => {
    cargarPruebas();
  }, [
    idPaciente,
    idSesion,
    tokenProp
  ]);

  /* ==================================================
     OBTENER HABILITACIONES DEL CONTEXTO ACTUAL

     Sesión:
       solo habilitaciones de esa sesión.

     Independiente:
       solo habilitaciones con id_sesion NULL.

     Se ordenan por ID para asegurar que la aplicación
     más reciente sea la que controla el estado actual.
  ================================================== */

  const obtenerHabilitacionesContexto = (
    idPrueba
  ) => {
    return pruebasHabilitadas
      .filter((habilitacion) => {
        const mismaPrueba =
          Number(habilitacion.id_prueba) ===
          Number(idPrueba);

        if (!mismaPrueba) {
          return false;
        }

        const sesionHabilitacion =
          habilitacion.id_sesion !== null &&
          habilitacion.id_sesion !== undefined &&
          habilitacion.id_sesion !== ""
            ? Number(habilitacion.id_sesion)
            : null;

        if (idSesionActual !== null) {
          return (
            sesionHabilitacion ===
            idSesionActual
          );
        }

        return sesionHabilitacion === null;
      })
      .sort(
        (a, b) =>
          Number(b.id_habilitacion) -
          Number(a.id_habilitacion)
      );
  };

  /* ==================================================
     OBTENER ÚLTIMA HABILITACIÓN DEL CONTEXTO

     IMPORTANTE:
     Si una prueba fue aplicada varias veces, usamos
     la habilitación más reciente para saber si existe
     una aplicación pendiente actualmente.
  ================================================== */

  const obtenerHabilitacionActual = (
    idPrueba
  ) => {
    const habilitaciones =
      obtenerHabilitacionesContexto(
        idPrueba
      );

    return habilitaciones.length
      ? habilitaciones[0]
      : null;
  };

  /* ==================================================
     SABER SI UNA HABILITACIÓN YA FUE COMPLETADA
  ================================================== */

  const habilitacionCompletada = (
    habilitacion
  ) => {
    if (!habilitacion) {
      return false;
    }

    return (
      Number(habilitacion.completada) === 1 ||
      Boolean(habilitacion.id_resultado)
    );
  };

  /* ==================================================
     GENERAR NUEVA HABILITACIÓN / ENLACE

     Esta misma función sirve para:
     - primera aplicación
     - aplicar nuevamente

     El backend genera un NUEVO id_habilitacion.
     Nunca se borra ni se reemplaza el resultado anterior.
  ================================================== */

  const generarEnlace = async (
    prueba
  ) => {
    if (!idPaciente) {
      alert(
        "⚠️ Primero selecciona un paciente."
      );
      return;
    }

    try {
      setLoadingHabilitar(
        prueba.id_prueba
      );

      setErrorMsg("");

      const response = await axios.post(
        `${API_URL}/api/evaluation/pruebas/habilitar`,
        {
          id_paciente:
            Number(idPaciente),

          id_prueba:
            Number(prueba.id_prueba),

          id_sesion:
            idSesionActual
        },
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      console.log(
        "✅ Prueba habilitada:",
        response.data
      );

      const idHabilitacion =
        response.data?.id_habilitacion;

      if (!idHabilitacion) {
        throw new Error(
          "El servidor no devolvió el ID de habilitación."
        );
      }

      const frontendUrl =
        window.location.origin;

      const enlace =
        `${frontendUrl}/prueba/${idHabilitacion}`;

      setEnlaceGenerado(enlace);

      setPruebaGenerada({
        ...prueba,
        id_habilitacion:
          idHabilitacion,
        id_sesion:
          idSesionActual
      });

      await cargarPruebas();
    } catch (error) {
      console.error(
        "❌ Error generando enlace:",
        error
      );

      alert(
        error?.response?.data?.message ||
        error?.message ||
        "❌ No se pudo generar el enlace."
      );
    } finally {
      setLoadingHabilitar(null);
    }
  };

  /* ==================================================
     APLICAR NUEVAMENTE

     No reinicia la aplicación anterior.
     Crea una habilitación completamente nueva.
  ================================================== */

  const aplicarNuevamente = async (
    prueba
  ) => {
    const confirmar = window.confirm(
      `¿Deseas aplicar nuevamente "${prueba.nombre}"?\n\n` +
      "Se generará un nuevo enlace y el resultado anterior se conservará en el historial."
    );

    if (!confirmar) {
      return;
    }

    await generarEnlace(prueba);
  };

  /* ==================================================
     MOSTRAR ENLACE PENDIENTE EXISTENTE
  ================================================== */

  const mostrarEnlaceExistente = (
    prueba
  ) => {
    const encontrada =
      obtenerHabilitacionActual(
        prueba.id_prueba
      );

    if (!encontrada?.id_habilitacion) {
      alert(
        "No se encontró la habilitación de esta prueba."
      );
      return;
    }

    if (
      habilitacionCompletada(
        encontrada
      )
    ) {
      alert(
        "Esta aplicación ya fue completada. Para volver a aplicarla utiliza “Aplicar nuevamente”."
      );
      return;
    }

    const frontendUrl =
      window.location.origin;

    const enlace =
      `${frontendUrl}/prueba/${encontrada.id_habilitacion}`;

    setEnlaceGenerado(enlace);

    setPruebaGenerada({
      ...prueba,
      id_habilitacion:
        encontrada.id_habilitacion,
      id_sesion:
        encontrada.id_sesion
    });
  };

  /* ==================================================
     COPIAR ENLACE
  ================================================== */

  const copiarEnlace = async () => {
    if (!enlaceGenerado) {
      return;
    }

    try {
      await navigator.clipboard.writeText(
        enlaceGenerado
      );

      alert(
        "✅ Enlace copiado al portapapeles."
      );
    } catch (error) {
      console.error(
        "Error copiando enlace:",
        error
      );

      alert(
        "No se pudo copiar automáticamente. Copia el enlace manualmente."
      );
    }
  };

  /* ==================================================
     CERRAR ENLACE
  ================================================== */

  const cerrarEnlace = () => {
    setEnlaceGenerado("");
    setPruebaGenerada(null);
  };

  /* ==================================================
     ESTADO DE CARGA
  ================================================== */

  if (loading) {
    return (
      <div style={container}>
        <h2 style={title}>
          🧪 Pruebas psicológicas
        </h2>

        <p style={subtitle}>
          Cargando pruebas disponibles...
        </p>

        <div style={loadingBox}>
          ⏳ Cargando...
        </div>
      </div>
    );
  }

  /* ==================================================
     VISTA
  ================================================== */

  return (
    <div style={container}>
      <h2 style={title}>
        🧪 Pruebas psicológicas
      </h2>

      <p style={subtitle}>
        {idSesionActual !== null
          ? `Selecciona una prueba para habilitarla dentro de la sesión #${idSesionActual}.`
          : "Selecciona una prueba para generar un enlace y enviárselo al paciente."}
      </p>

      {/* PACIENTE / CONTEXTO */}

      <div style={patientBox}>
        <div>
          👤 <strong>
            Paciente #{idPaciente}
          </strong>
        </div>

        <div style={contextRow}>
          {idSesionActual !== null ? (
            <span style={sessionBadge}>
              🩺 Sesión #{idSesionActual}
            </span>
          ) : (
            <span style={independentBadge}>
              📋 Evaluación independiente
            </span>
          )}
        </div>
      </div>

      {/* EXPLICACIÓN DEL CONTEXTO */}

      {idSesionActual !== null ? (
        <div style={sessionInfoBox}>
          <strong>
            🔗 Prueba vinculada a sesión
          </strong>

          <div style={sessionInfoText}>
            Las respuestas y el resultado de esta
            evaluación se guardarán automáticamente
            dentro de la sesión #{idSesionActual}.
          </div>
        </div>
      ) : (
        <div style={independentInfoBox}>
          <strong>
            📋 Evaluación fuera de sesión
          </strong>

          <div style={sessionInfoText}>
            Esta prueba quedará registrada en el
            expediente general del paciente y no
            pertenecerá a una sesión clínica
            específica.
          </div>
        </div>
      )}

      {/* ERROR */}

      {errorMsg && (
        <div style={errorBox}>
          ❌ {errorMsg}
        </div>
      )}

      {/* ENLACE GENERADO */}

      {enlaceGenerado && (
        <div style={linkBox}>
          <div style={linkHeader}>
            <div>
              <div style={linkTitle}>
                🔗 Enlace generado
              </div>

              <div style={linkSubtitle}>
                {pruebaGenerada?.nombre}
              </div>
            </div>

            <button
              type="button"
              style={closeButton}
              onClick={cerrarEnlace}
            >
              ✕
            </button>
          </div>

          {pruebaGenerada?.id_sesion ? (
            <div style={linkSessionBadge}>
              🩺 Asociada a sesión #
              {pruebaGenerada.id_sesion}
            </div>
          ) : (
            <div style={linkIndependentBadge}>
              📋 Evaluación independiente
            </div>
          )}

          <p style={linkDescription}>
            Envía este enlace al paciente para que
            pueda responder la prueba desde su
            dispositivo.
          </p>

          <div style={linkInputContainer}>
            <input
              value={enlaceGenerado}
              readOnly
              style={linkInput}
              onClick={(e) =>
                e.target.select()
              }
            />

            <button
              type="button"
              style={copyButton}
              onClick={copiarEnlace}
            >
              📋 Copiar enlace
            </button>
          </div>

          <div style={linkWarning}>
            ⚠️ El paciente no necesita iniciar sesión
            para responder esta prueba.
          </div>
        </div>
      )}

      {/* PRUEBAS DISPONIBLES */}

      <div style={section}>
        <div style={sectionHeader}>
          <div>
            <h3 style={sectionTitle}>
              📋 Pruebas disponibles
            </h3>

            <p style={sectionSubtitle}>
              {idSesionActual !== null
                ? `Selecciona una prueba para la sesión #${idSesionActual}.`
                : "Selecciona una prueba para habilitarla al paciente."}
            </p>
          </div>

          <span style={countBadge}>
            {pruebas.length} prueba
            {pruebas.length !== 1
              ? "s"
              : ""}
          </span>
        </div>

        {pruebas.length === 0 ? (
          <div style={emptyBox}>
            <div style={emptyIcon}>
              🧪
            </div>

            <h3>
              No hay pruebas disponibles
            </h3>

            <p>
              No existen pruebas activas registradas
              en el sistema.
            </p>
          </div>
        ) : (
          <div style={grid}>
            {pruebas.map((prueba) => {
              const habilitacionActual =
                obtenerHabilitacionActual(
                  prueba.id_prueba
                );

              const existeHabilitacion =
                Boolean(
                  habilitacionActual
                );

              const completada =
                habilitacionCompletada(
                  habilitacionActual
                );

              const generando =
                loadingHabilitar ===
                prueba.id_prueba;

              return (
                <div
                  key={prueba.id_prueba}
                  style={card}
                >
                  <div style={cardIcon}>
                    🧠
                  </div>

                  <h3 style={cardTitle}>
                    {prueba.nombre}
                  </h3>

                  <div style={typeBadge}>
                    {prueba.tipo}
                  </div>

                  <p style={cardDescription}>
                    {prueba.descripcion ||
                      "Prueba psicológica de evaluación."}
                  </p>

                  {/* ==================================
                      YA COMPLETADA
                  ================================== */}

                  {existeHabilitacion &&
                  completada ? (
                    <div style={completedBox}>
                      <div style={completedText}>
                        ✅ Evaluación completada
                      </div>

                      <div style={completedContext}>
                        {idSesionActual !== null
                          ? `Sesión #${idSesionActual}`
                          : "Evaluación independiente"}
                      </div>

                      {habilitacionActual
                        ?.interpretacion && (
                        <div
                          style={
                            resultInterpretation
                          }
                        >
                          {
                            habilitacionActual
                              .interpretacion
                          }
                        </div>
                      )}

                      {habilitacionActual
                        ?.puntaje_total !==
                        null &&
                        habilitacionActual
                          ?.puntaje_total !==
                          undefined && (
                          <div
                            style={resultScore}
                          >
                            Puntaje:{" "}
                            <strong>
                              {
                                habilitacionActual
                                  .puntaje_total
                              }
                            </strong>
                          </div>
                        )}

                      <button
                        type="button"
                        style={repeatButton}
                        disabled={generando}
                        onClick={() =>
                          aplicarNuevamente(
                            prueba
                          )
                        }
                      >
                        {generando
                          ? "⏳ Generando..."
                          : "🔄 Aplicar nuevamente"}
                      </button>
                    </div>
                  ) : existeHabilitacion ? (

                    /* ================================
                       HABILITADA / PENDIENTE
                    ================================ */

                    <div style={alreadyBox}>
                      <div style={alreadyText}>
                        {idSesionActual !== null
                          ? `✓ Habilitada en sesión #${idSesionActual}`
                          : "✓ Habilitada como evaluación independiente"}
                      </div>

                      <div style={pendingText}>
                        ⏳ Pendiente de responder
                      </div>

                      <button
                        type="button"
                        style={secondaryButton}
                        onClick={() =>
                          mostrarEnlaceExistente(
                            prueba
                          )
                        }
                      >
                        🔗 Ver enlace
                      </button>
                    </div>
                  ) : (

                    /* ================================
                       NUNCA HABILITADA
                    ================================ */

                    <button
                      type="button"
                      style={button}
                      disabled={generando}
                      onClick={() =>
                        generarEnlace(
                          prueba
                        )
                      }
                    >
                      {generando
                        ? "⏳ Generando..."
                        : idSesionActual !== null
                        ? "🔗 Habilitar en esta sesión"
                        : "🔗 Generar enlace"}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* CÓMO FUNCIONA */}

      <div style={infoBox}>
        <h3 style={infoTitle}>
          💡 ¿Cómo funciona?
        </h3>

        <ol style={steps}>
          <li>
            Selecciona una prueba.
          </li>

          <li>
            Genera el enlace.
          </li>

          <li>
            Copia el enlace.
          </li>

          <li>
            Envíalo al paciente.
          </li>

          <li>
            El paciente responde desde su dispositivo.
          </li>

          <li>
            Cuando una evaluación ya fue completada,
            puedes aplicarla nuevamente sin perder
            el resultado anterior.
          </li>

          {idSesionActual !== null && (
            <li>
              El resultado quedará asociado
              automáticamente a la sesión #
              {idSesionActual}.
            </li>
          )}
        </ol>
      </div>

      {/* VOLVER */}

      <button
        type="button"
        style={{
          ...backButton,
          background: "#1565C0",
          color: "#fff"
        }}
        onClick={onBack}
      >
        {idSesionActual !== null
          ? "⬅️ Regresar a la sesión"
          : "⬅️ Regresar al historial"}
      </button>

      <p style={footerText}>
        🌱 Las pruebas son herramientas de evaluación
        y sus resultados son preliminares. El psicólogo
        tiene siempre la decisión clínica final.
      </p>
    </div>
  );
}

/* ==================================================
   ESTILOS
================================================== */

const container = {
  maxWidth: "1000px",
  margin: "30px auto",
  padding: "30px",
  background: "#fff",
  borderRadius: "20px",
  boxShadow:
    "0 10px 30px rgba(0,0,0,0.08)"
};

const title = {
  fontSize: "28px",
  fontWeight: "700",
  color: "#263238",
  marginBottom: "8px"
};

const subtitle = {
  fontSize: "16px",
  color: "#607D8B",
  marginBottom: "20px"
};

const patientBox = {
  background:
    "linear-gradient(135deg, #E3F2FD, #F3E5F5)",
  padding: "15px 18px",
  borderRadius: "12px",
  marginBottom: "12px",
  color: "#37474F",
  border:
    "1px solid #CFD8DC"
};

const contextRow = {
  marginTop: "10px"
};

const sessionBadge = {
  display: "inline-block",
  background: "#E8F5E9",
  color: "#2E7D32",
  padding: "6px 11px",
  borderRadius: "20px",
  fontSize: "13px",
  fontWeight: "700",
  border:
    "1px solid #C8E6C9"
};

const independentBadge = {
  display: "inline-block",
  background: "#FFF8E1",
  color: "#8D6E63",
  padding: "6px 11px",
  borderRadius: "20px",
  fontSize: "13px",
  fontWeight: "700",
  border:
    "1px solid #FFE082"
};

const sessionInfoBox = {
  background: "#E8F5E9",
  color: "#2E7D32",
  padding: "13px 16px",
  borderRadius: "10px",
  border:
    "1px solid #C8E6C9",
  marginBottom: "20px"
};

const independentInfoBox = {
  background: "#FFFDE7",
  color: "#795548",
  padding: "13px 16px",
  borderRadius: "10px",
  border:
    "1px solid #FFF59D",
  marginBottom: "20px"
};

const sessionInfoText = {
  marginTop: "5px",
  fontSize: "13px",
  lineHeight: "1.5"
};

const errorBox = {
  background: "#FFEBEE",
  color: "#C62828",
  padding: "14px",
  borderRadius: "10px",
  marginBottom: "20px",
  border:
    "1px solid #FFCDD2"
};

const loadingBox = {
  padding: "30px",
  textAlign: "center",
  color: "#607D8B",
  background: "#F5F7FA",
  borderRadius: "12px"
};

const linkBox = {
  background:
    "linear-gradient(135deg, #E8F5E9, #E3F2FD)",
  border:
    "1px solid #B2DFDB",
  padding: "20px",
  borderRadius: "16px",
  marginBottom: "25px"
};

const linkHeader = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start"
};

const linkTitle = {
  fontSize: "20px",
  fontWeight: "700",
  color: "#1565C0"
};

const linkSubtitle = {
  marginTop: "4px",
  color: "#546E7A",
  fontWeight: "600"
};

const linkSessionBadge = {
  display: "inline-block",
  marginTop: "12px",
  padding: "5px 10px",
  background: "#C8E6C9",
  color: "#2E7D32",
  borderRadius: "14px",
  fontSize: "12px",
  fontWeight: "700"
};

const linkIndependentBadge = {
  display: "inline-block",
  marginTop: "12px",
  padding: "5px 10px",
  background: "#FFF3E0",
  color: "#E65100",
  borderRadius: "14px",
  fontSize: "12px",
  fontWeight: "700"
};

const linkDescription = {
  color: "#455A64",
  lineHeight: "1.5"
};

const linkInputContainer = {
  display: "flex",
  gap: "10px",
  marginTop: "15px"
};

const linkInput = {
  flex: 1,
  padding: "12px",
  border:
    "1px solid #B0BEC5",
  borderRadius: "8px",
  background: "#fff",
  fontSize: "14px"
};

const copyButton = {
  padding: "12px 18px",
  border: "none",
  borderRadius: "8px",
  background: "#2E7D32",
  color: "#fff",
  fontWeight: "700",
  cursor: "pointer"
};

const closeButton = {
  border: "none",
  background: "transparent",
  fontSize: "20px",
  cursor: "pointer",
  color: "#607D8B"
};

const linkWarning = {
  marginTop: "14px",
  fontSize: "13px",
  color: "#546E7A"
};

const section = {
  marginTop: "25px"
};

const sectionHeader = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  marginBottom: "18px"
};

const sectionTitle = {
  margin: 0,
  fontSize: "20px",
  color: "#263238"
};

const sectionSubtitle = {
  margin: "5px 0 0",
  color: "#78909C"
};

const countBadge = {
  background: "#E3F2FD",
  color: "#1565C0",
  padding: "7px 12px",
  borderRadius: "20px",
  fontSize: "13px",
  fontWeight: "700"
};

const grid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(280px, 1fr))",
  gap: "18px"
};

const card = {
  background: "#FAFAFA",
  border:
    "1px solid #E0E0E0",
  borderRadius: "16px",
  padding: "20px",
  transition: "0.2s",
  boxShadow:
    "0 3px 10px rgba(0,0,0,0.05)"
};

const cardIcon = {
  fontSize: "32px",
  marginBottom: "8px"
};

const cardTitle = {
  fontSize: "18px",
  fontWeight: "700",
  color: "#263238",
  marginBottom: "8px"
};

const typeBadge = {
  display: "inline-block",
  background: "#E8EAF6",
  color: "#3949AB",
  padding: "5px 10px",
  borderRadius: "15px",
  fontSize: "12px",
  fontWeight: "700",
  marginBottom: "12px"
};

const cardDescription = {
  color: "#607D8B",
  fontSize: "14px",
  lineHeight: "1.5",
  minHeight: "45px"
};

const button = {
  width: "100%",
  marginTop: "15px",
  padding: "12px",
  border: "none",
  borderRadius: "9px",
  background: "#5C6BC0",
  color: "#fff",
  fontWeight: "700",
  cursor: "pointer"
};

const secondaryButton = {
  width: "100%",
  marginTop: "10px",
  padding: "10px",
  border:
    "1px solid #5C6BC0",
  borderRadius: "9px",
  background: "#fff",
  color: "#3949AB",
  fontWeight: "700",
  cursor: "pointer"
};

const alreadyBox = {
  marginTop: "12px",
  padding: "10px",
  background: "#E8F5E9",
  borderRadius: "9px"
};

const alreadyText = {
  color: "#2E7D32",
  fontSize: "13px",
  fontWeight: "700"
};

const pendingText = {
  marginTop: "6px",
  color: "#EF6C00",
  fontSize: "12px",
  fontWeight: "600"
};

const completedBox = {
  marginTop: "12px",
  padding: "12px",
  background: "#E8F5E9",
  borderRadius: "9px",
  border:
    "1px solid #C8E6C9"
};

const completedText = {
  color: "#2E7D32",
  fontSize: "14px",
  fontWeight: "700"
};

const completedContext = {
  marginTop: "5px",
  color: "#607D8B",
  fontSize: "12px"
};

const resultInterpretation = {
  marginTop: "9px",
  padding: "7px 9px",
  background: "#fff",
  borderRadius: "7px",
  color: "#37474F",
  fontSize: "13px",
  fontWeight: "600"
};

const resultScore = {
  marginTop: "6px",
  color: "#546E7A",
  fontSize: "12px"
};

const repeatButton = {
  width: "100%",
  marginTop: "11px",
  padding: "10px",
  border:
    "1px solid #1565C0",
  borderRadius: "9px",
  background: "#fff",
  color: "#1565C0",
  fontWeight: "700",
  cursor: "pointer"
};

const emptyBox = {
  textAlign: "center",
  padding: "45px 20px",
  background: "#F8F9FA",
  borderRadius: "15px",
  border:
    "1px dashed #CFD8DC"
};

const emptyIcon = {
  fontSize: "45px",
  marginBottom: "10px"
};

const infoBox = {
  marginTop: "30px",
  padding: "20px",
  background: "#FFF8E1",
  borderRadius: "14px",
  border:
    "1px solid #FFE082"
};

const infoTitle = {
  marginTop: 0,
  color: "#795548"
};

const steps = {
  margin: 0,
  paddingLeft: "22px",
  color: "#5D4037",
  lineHeight: "1.9"
};

const backButton = {
  marginTop: "25px",
  padding: "12px 20px",
  border: "none",
  borderRadius: "9px",
  background: "#E74C3C",
  color: "#fff",
  fontWeight: "700",
  cursor: "pointer"
};

const footerText = {
  marginTop: "18px",
  textAlign: "center",
  color: "#78909C",
  fontSize: "13px"
};