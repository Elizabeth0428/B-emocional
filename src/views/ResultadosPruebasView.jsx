// src/views/ResultadosPruebasView.jsx

import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

export default function ResultadosPruebasView() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();

  const [resultados, setResultados] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // =====================================================
  // IDENTIFICAR CLEAVER
  // =====================================================

  const esCleaver = (resultado) => {
    return (
      Number(resultado?.id_prueba) === 4 ||
      String(resultado?.tipo || "").toLowerCase() === "cleaver" ||
      String(
        resultado?.prueba ||
        resultado?.nombre_prueba ||
        ""
      )
        .toLowerCase()
        .includes("cleaver")
    );
  };

  // =====================================================
  // CARGAR DETALLE CLEAVER
  // =====================================================

  const cargarDetalleCleaver = async (resultado, token) => {
    if (
      !esCleaver(resultado) ||
      !resultado?.id_habilitacion
    ) {
      return resultado;
    }

    try {
      const res = await fetch(
        `${API_URL}/api/cleaver/resultado/${resultado.id_habilitacion}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!res.ok) {
        console.warn(
          "⚠️ No se pudo cargar detalle Cleaver:",
          resultado.id_habilitacion
        );

        return {
          ...resultado,
          cleaver: null,
        };
      }

      const detalle = await res.json();

      console.log(
        "📊 Detalle Cleaver:",
        detalle
      );

      return {
        ...resultado,
        cleaver: detalle,
      };
    } catch (err) {
      console.error(
        "❌ Error cargando detalle Cleaver:",
        err
      );

      return {
        ...resultado,
        cleaver: null,
      };
    }
  };

  // =====================================================
  // CARGAR RESULTADOS
  // =====================================================

  useEffect(() => {
    const fetchResultados = async () => {
      try {
        setLoading(true);
        setError("");

        const token = getToken();

        const res = await fetch(
          `${API_URL}/api/evaluation/resultados/${idPaciente}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!res.ok) {
          throw new Error(
            "No se pudieron obtener los resultados"
          );
        }

        const data = await res.json();

        console.log(
          "🧪 Resultados recibidos:",
          data
        );

        const lista = Array.isArray(data)
          ? data
          : data.resultados || [];

        const resultadosCompletos =
          await Promise.all(
            lista.map((resultado) =>
              cargarDetalleCleaver(
                resultado,
                token
              )
            )
          );

        setResultados(
          resultadosCompletos
        );
      } catch (err) {
        console.error(
          "❌ Error al obtener resultados:",
          err
        );

        setError(
          "No fue posible cargar los resultados de las pruebas."
        );
      } finally {
        setLoading(false);
      }
    };

    if (idPaciente) {
      fetchResultados();
    } else {
      setLoading(false);

      setError(
        "No se encontró el paciente."
      );
    }
  }, [idPaciente]);

  // =====================================================
  // VOLVER AL EXPEDIENTE
  // =====================================================

  const volverAlExpediente = () => {
    navigate(
      `/paciente/${idPaciente}`
    );
  };

  // =====================================================
  // FORMATEAR FECHA
  // =====================================================

  const formatearFecha = (fecha) => {
    if (!fecha) {
      return "No registrada";
    }

    const fechaObj =
      new Date(fecha);

    if (
      Number.isNaN(
        fechaObj.getTime()
      )
    ) {
      return "No registrada";
    }

    return fechaObj.toLocaleDateString(
      "es-MX",
      {
        day: "2-digit",
        month: "long",
        year: "numeric",
      }
    );
  };

  // =====================================================
  // COMPONENTE FACTOR CLEAVER
  // =====================================================

  const FactorCleaver = ({
    factor,
    bruto,
    posicion,
  }) => {
    return (
      <div style={factorBox}>
        <div style={factorName}>
          {factor}
        </div>

        <div style={factorValue}>
          {bruto ?? "—"}
        </div>

        <div style={factorPosition}>
          Posición:{" "}
          {posicion !== null &&
          posicion !== undefined
            ? Number(posicion).toFixed(2)
            : "—"}
        </div>
      </div>
    );
  };

  // =====================================================
  // BLOQUE PATRÓN CLEAVER
  // =====================================================

  const PatronCleaver = ({
    titulo,
    descripcion,
    bruto,
    posiciones,
  }) => {
    return (
      <div style={cleaverPattern}>
        <div style={patternHeader}>
          <div>
            <div style={patternTitle}>
              {titulo}
            </div>

            <div style={patternDescription}>
              {descripcion}
            </div>
          </div>
        </div>

        <div style={factorGrid}>
          <FactorCleaver
            factor="D"
            bruto={bruto?.D}
            posicion={posiciones?.D}
          />

          <FactorCleaver
            factor="I"
            bruto={bruto?.I}
            posicion={posiciones?.I}
          />

          <FactorCleaver
            factor="S"
            bruto={bruto?.S}
            posicion={posiciones?.S}
          />

          <FactorCleaver
            factor="C"
            bruto={bruto?.C}
            posicion={posiciones?.C}
          />
        </div>
      </div>
    );
  };

  // =====================================================
  // GRÁFICA CLEAVER
  // =====================================================

  const GraficaCleaver = ({
    titulo,
    subtitulo,
    bruto,
    posiciones,
  }) => {
    const factores = [
      "D",
      "I",
      "S",
      "C"
    ];

    const x = {
      D: 70,
      I: 155,
      S: 240,
      C: 325,
    };

    const top = 30;
    const bottom = 275;
    const alto = bottom - top;

    const posicionY = (valor) => {
      const n = Number(valor);

      if (
        Number.isNaN(n)
      ) {
        return bottom;
      }

      const limitada =
        Math.max(
          1,
          Math.min(
            99,
            n
          )
        );

      return (
        top +
        ((99 - limitada) / 98) *
          alto
      );
    };

    const puntos = factores
      .filter(
        factor =>
          posiciones?.[factor] !== null &&
          posiciones?.[factor] !== undefined
      )
      .map(
        factor =>
          `${x[factor]},${posicionY(
            posiciones[factor]
          )}`
      )
      .join(" ");

    const lineas = [
      99,
      95,
      90,
      84,
      80,
      70,
      60,
      50,
      40,
      30,
      20,
      16,
      10,
      5,
      1,
    ];

    return (
      <div style={graphCard}>
        <div style={graphHeader}>
          <div style={graphTitle}>
            {titulo}
          </div>

          <div style={graphSubtitle}>
            {subtitulo}
          </div>
        </div>

        <svg
          viewBox="0 0 390 325"
          style={graphSvg}
          role="img"
          aria-label={`Gráfica Cleaver ${titulo}`}
        >
          {/* ESCALA HORIZONTAL */}

          {lineas.map(
            (valor) => {
              const y =
                posicionY(valor);

              const esLineaMedia =
                valor === 50;

              return (
                <g
                  key={
                    `horizontal-${valor}`
                  }
                >
                  <line
                    x1="48"
                    x2="350"
                    y1={y}
                    y2={y}
                    stroke={
                      esLineaMedia
                        ? "#94a3b8"
                        : "#e2e8f0"
                    }
                    strokeWidth={
                      esLineaMedia
                        ? "1.5"
                        : "1"
                    }
                    strokeDasharray={
                      esLineaMedia
                        ? "4 4"
                        : "0"
                    }
                  />

                  <text
                    x="39"
                    y={y + 3}
                    textAnchor="end"
                    fontSize="8"
                    fill="#94a3b8"
                  >
                    {valor}
                  </text>
                </g>
              );
            }
          )}

          {/* COLUMNAS D I S C */}

          {factores.map(
            (factor) => (
              <line
                key={
                  `vertical-${factor}`
                }
                x1={x[factor]}
                x2={x[factor]}
                y1={top}
                y2={bottom}
                stroke="#edf2f7"
                strokeWidth="1"
              />
            )
          )}

          {/* LÍNEA RESULTADO */}

          {puntos && (
            <polyline
              points={puntos}
              fill="none"
              stroke="#3157a6"
              strokeWidth="3"
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          )}

          {/* PUNTOS */}

          {factores.map(
            (factor) => {
              const posicion =
                posiciones?.[
                  factor
                ];

              if (
                posicion === null ||
                posicion === undefined
              ) {
                return null;
              }

              const y =
                posicionY(
                  posicion
                );

              return (
                <g
                  key={
                    `punto-${factor}`
                  }
                >
                  <circle
                    cx={
                      x[factor]
                    }
                    cy={y}
                    r="7"
                    fill="#3157a6"
                    stroke="#ffffff"
                    strokeWidth="3"
                  />

                  <text
                    x={
                      x[factor]
                    }
                    y={y - 13}
                    textAnchor="middle"
                    fontSize="11"
                    fontWeight="800"
                    fill="#3157a6"
                  >
                    {Number(
                      posicion
                    ).toFixed(0)}
                  </text>
                </g>
              );
            }
          )}

          {/* FACTORES Y BRUTOS */}

          {factores.map(
            (factor) => (
              <g
                key={
                  `label-${factor}`
                }
              >
                <text
                  x={
                    x[factor]
                  }
                  y="297"
                  textAnchor="middle"
                  fontSize="15"
                  fontWeight="800"
                  fill="#334155"
                >
                  {factor}
                </text>

                <text
                  x={
                    x[factor]
                  }
                  y="313"
                  textAnchor="middle"
                  fontSize="9"
                  fill="#64748b"
                >
                  Bruto{" "}
                  {bruto?.[
                    factor
                  ] ?? "—"}
                </text>
              </g>
            )
          )}
        </svg>

        <div style={graphLegend}>
          Escala de posición gráfica Cleaver
        </div>
      </div>
    );
  };

  // =====================================================
  // RESULTADO CLEAVER
  // =====================================================

  const ResultadoCleaver = ({
    resultado,
  }) => {
    const detalle =
      resultado?.cleaver;

    if (!detalle) {
      return (
        <div style={cleaverWarning}>
          ⚠️ El resultado Cleaver fue
          registrado, pero no fue posible
          cargar su detalle M/L/T.
        </div>
      );
    }

    const bruto =
      detalle.bruto ||
      detalle.resultado ||
      {};

    const posiciones =
      detalle.posiciones ||
      {};

    return (
      <>
        {/* ============================================
            INTRO
        ============================================ */}

        <div style={cleaverIntro}>
          <div style={cleaverIntroIcon}>
            📈
          </div>

          <div>
            <div style={cleaverIntroTitle}>
              Perfil Cleaver
            </div>

            <div style={cleaverIntroText}>
              Resultado multidimensional
              D / I / S / C
            </div>
          </div>
        </div>

        {/* ============================================
            VALORES M / L / T
        ============================================ */}

        <div style={cleaverPatterns}>
          <PatronCleaver
            titulo="MÁS · M"
            descripcion="Comportamiento que la persona identifica como más representativo."
            bruto={bruto.M}
            posiciones={
              posiciones.M
            }
          />

          <PatronCleaver
            titulo="MENOS · L"
            descripcion="Comportamiento que la persona identifica como menos representativo."
            bruto={bruto.L}
            posiciones={
              posiciones.L
            }
          />

          <PatronCleaver
            titulo="TOTAL · T"
            descripcion="Resultado obtenido mediante M − L."
            bruto={bruto.T}
            posiciones={
              posiciones.T
            }
          />
        </div>

        {/* ============================================
            GRÁFICAS
        ============================================ */}

        <div style={graphsSection}>
          <div style={graphsHeader}>
            <div>
              <div style={graphsTitle}>
                Gráficas Cleaver
              </div>

              <div style={graphsDescription}>
                Representación visual de las
                dimensiones D, I, S y C según
                su posición gráfica.
              </div>
            </div>
          </div>

          <div style={graphsGrid}>
            <GraficaCleaver
              titulo="M · MÁS"
              subtitulo="Comportamiento percibido como más representativo"
              bruto={bruto.M}
              posiciones={
                posiciones.M
              }
            />

            <GraficaCleaver
              titulo="L · MENOS"
              subtitulo="Comportamiento percibido como menos representativo"
              bruto={bruto.L}
              posiciones={
                posiciones.L
              }
            />

            <GraficaCleaver
              titulo="T · TOTAL"
              subtitulo="Perfil resultante M − L"
              bruto={bruto.T}
              posiciones={
                posiciones.T
              }
            />
          </div>
        </div>

        {/* ============================================
            PERFIL
        ============================================ */}

        {detalle.perfil_principal ? (
          <div style={profileBox}>
            <div style={profileIcon}>
              🧠
            </div>

            <div>
              <div style={profileLabel}>
                PERFIL PRINCIPAL
              </div>

              <div style={profileValue}>
                {
                  detalle.perfil_principal
                }
              </div>
            </div>
          </div>
        ) : null}

        {/* ============================================
            INTERPRETACIÓN
        ============================================ */}

        <div style={interpretation}>
          <div
            style={
              interpretationHeader
            }
          >
            <span
              style={
                interpretationIcon
              }
            >
              📖
            </span>

            <span
              style={
                interpretationTitle
              }
            >
              Interpretación
            </span>
          </div>

          <p style={interpretationText}>
            {detalle.interpretacion ||
              "El cálculo M/L/T ya está disponible. El perfil e interpretación Cleaver se incorporarán en la siguiente etapa de evaluación."}
          </p>
        </div>
      </>
    );
  };

  // =====================================================
  // CARGANDO
  // =====================================================

  if (loading) {
    return (
      <div style={page}>
        <div style={loadingCard}>
          <div style={loadingIcon}>
            🧪
          </div>

          <h2 style={loadingTitle}>
            Cargando resultados...
          </h2>

          <p style={loadingText}>
            Estamos consultando los
            resultados de las pruebas
            psicológicas del paciente.
          </p>
        </div>
      </div>
    );
  }

  // =====================================================
  // ERROR
  // =====================================================

  if (error) {
    return (
      <div style={page}>
        <div style={errorCard}>
          <div style={errorIcon}>
            ⚠️
          </div>

          <h2 style={errorTitle}>
            No se pudieron cargar los
            resultados
          </h2>

          <p style={errorText}>
            {error}
          </p>

          <button
            type="button"
            onClick={
              volverAlExpediente
            }
            style={backButton}
          >
            ← Volver al expediente
          </button>
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
        {/* =============================================
            ENCABEZADO
        ============================================= */}

        <div style={header}>
          <button
            type="button"
            onClick={
              volverAlExpediente
            }
            style={backButton}
          >
            ← Volver al expediente
          </button>

          <div style={headerContent}>
            <div style={headerIcon}>
              🧪
            </div>

            <div>
              <div style={eyebrow}>
                EXPEDIENTE CLÍNICO
              </div>

              <h1 style={title}>
                Resultados de pruebas
              </h1>

              <p style={subtitle}>
                Consulta los resultados
                e interpretaciones de
                las pruebas psicológicas
                realizadas.
              </p>
            </div>
          </div>
        </div>

        {/* =============================================
            RESUMEN
        ============================================= */}

        <div style={summaryCard}>
          <div style={summaryIcon}>
            📊
          </div>

          <div>
            <div style={summaryLabel}>
              RESULTADOS REGISTRADOS
            </div>

            <div style={summaryNumber}>
              {resultados.length}
            </div>
          </div>

          <div
            style={
              summaryDescription
            }
          >
            {resultados.length === 0
              ? "El paciente todavía no cuenta con resultados registrados."
              : resultados.length === 1
              ? "Se encontró un resultado registrado."
              : "Se encontraron resultados de pruebas realizadas."}
          </div>
        </div>

        {/* =============================================
            SIN RESULTADOS
        ============================================= */}

        {resultados.length === 0 ? (
          <div style={emptyCard}>
            <div style={emptyIcon}>
              🧪
            </div>

            <h2 style={emptyTitle}>
              No hay resultados todavía
            </h2>

            <p style={emptyText}>
              Cuando el paciente
              complete una prueba
              psicológica, sus
              resultados aparecerán
              aquí.
            </p>

            <button
              type="button"
              onClick={
                volverAlExpediente
              }
              style={emptyButton}
            >
              ← Volver al expediente
            </button>
          </div>
        ) : (
          <div style={resultsSection}>
            <div style={sectionHeader}>
              <div>
                <h2 style={sectionTitle}>
                  📋 Historial de resultados
                </h2>

                <p
                  style={
                    sectionDescription
                  }
                >
                  Resultados obtenidos
                  en las pruebas
                  psicológicas.
                </p>
              </div>
            </div>

            <div style={resultsGrid}>
              {resultados.map(
                (
                  resultado,
                  index
                ) => {
                  const cleaver =
                    esCleaver(
                      resultado
                    );

                  return (
                    <div
                      key={
                        resultado.id_resultado ||
                        `${resultado.id_prueba}-${index}`
                      }
                      style={{
                        ...resultCard,
                        ...(cleaver
                          ? cleaverCard
                          : {}),
                      }}
                    >
                      {/* =====================================
                          CABECERA
                      ===================================== */}

                      <div
                        style={
                          resultHeader
                        }
                      >
                        <div
                          style={
                            resultNumber
                          }
                        >
                          {index + 1}
                        </div>

                        <div
                          style={
                            resultTitleContainer
                          }
                        >
                          <div
                            style={
                              resultLabel
                            }
                          >
                            PRUEBA PSICOLÓGICA
                          </div>

                          <h3
                            style={
                              resultTitle
                            }
                          >
                            {resultado.prueba ||
                              resultado.nombre_prueba ||
                              "Prueba sin nombre"}
                          </h3>
                        </div>
                      </div>

                      {/* =====================================
                          CLEAVER
                      ===================================== */}

                      {cleaver ? (
                        <>
                          <div
                            style={
                              cleaverDate
                            }
                          >
                            <span>
                              📅
                            </span>

                            <span>
                              {formatearFecha(
                                resultado.fecha ||
                                  resultado
                                    ?.cleaver
                                    ?.fecha
                              )}
                            </span>
                          </div>

                          <ResultadoCleaver
                            resultado={
                              resultado
                            }
                          />
                        </>
                      ) : (
                        <>
                          {/* ================================
                              RESULTADO NORMAL
                          ================================ */}

                          <div
                            style={
                              resultInfo
                            }
                          >
                            <div
                              style={
                                infoBox
                              }
                            >
                              <span
                                style={
                                  infoBoxIcon
                                }
                              >
                                ⭐
                              </span>

                              <div>
                                <div
                                  style={
                                    infoBoxLabel
                                  }
                                >
                                  Puntaje
                                </div>

                                <div
                                  style={
                                    score
                                  }
                                >
                                  {resultado.puntaje_total ??
                                    "—"}
                                </div>
                              </div>
                            </div>

                            <div
                              style={
                                infoBox
                              }
                            >
                              <span
                                style={
                                  infoBoxIcon
                                }
                              >
                                📅
                              </span>

                              <div>
                                <div
                                  style={
                                    infoBoxLabel
                                  }
                                >
                                  Fecha
                                </div>

                                <div
                                  style={
                                    infoBoxValue
                                  }
                                >
                                  {formatearFecha(
                                    resultado.fecha
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>

                          <div
                            style={
                              interpretation
                            }
                          >
                            <div
                              style={
                                interpretationHeader
                              }
                            >
                              <span
                                style={
                                  interpretationIcon
                                }
                              >
                                📖
                              </span>

                              <span
                                style={
                                  interpretationTitle
                                }
                              >
                                Interpretación
                              </span>
                            </div>

                            <p
                              style={
                                interpretationText
                              }
                            >
                              {resultado.interpretacion ||
                                "No se registró una interpretación para este resultado."}
                            </p>
                          </div>
                        </>
                      )}
                    </div>
                  );
                }
              )}
            </div>
          </div>
        )}

        {/* =============================================
            PIE
        ============================================= */}

        <div style={footer}>
          <span>
            🧠 MirrorSoul
          </span>

          <span>
            Expediente del paciente #
            {idPaciente}
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
  padding: "30px 20px 50px",
  boxSizing: "border-box",
  background:
    "linear-gradient(135deg, #eef5ff 0%, #f8fbff 45%, #eef4ff 100%)",
  fontFamily:
    "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
};

const container = {
  width: "100%",
  maxWidth: "1100px",
  margin: "0 auto",
};

// =====================================================
// HEADER
// =====================================================

const header = {
  marginBottom: "25px",
};

const backButton = {
  border: "none",
  background: "#ffffff",
  color: "#3157a6",
  padding: "10px 16px",
  borderRadius: "12px",
  cursor: "pointer",
  fontWeight: "700",
  fontSize: "14px",
  boxShadow:
    "0 5px 16px rgba(40,70,120,0.08)",
  marginBottom: "22px",
  transition: "all 0.2s ease",
};

const headerContent = {
  display: "flex",
  alignItems: "center",
  gap: "18px",
  background: "#ffffff",
  padding: "25px",
  borderRadius: "20px",
  border:
    "1px solid #e2e8f0",
  boxShadow:
    "0 8px 25px rgba(30,70,120,0.08)",
};

const headerIcon = {
  width: "65px",
  height: "65px",
  flexShrink: 0,
  borderRadius: "18px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "30px",
  background:
    "linear-gradient(135deg, #e3f2fd, #dbe8ff)",
};

const eyebrow = {
  fontSize: "11px",
  fontWeight: "800",
  letterSpacing: "2px",
  color: "#5c6bc0",
  marginBottom: "5px",
};

const title = {
  margin: 0,
  color: "#173b70",
  fontSize: "28px",
  fontWeight: "800",
};

const subtitle = {
  margin: "7px 0 0",
  color: "#718096",
  fontSize: "14px",
  lineHeight: "1.5",
};

// =====================================================
// RESUMEN
// =====================================================

const summaryCard = {
  display: "flex",
  alignItems: "center",
  gap: "16px",
  background: "#ffffff",
  borderRadius: "18px",
  padding: "20px 24px",
  marginBottom: "28px",
  border:
    "1px solid #e2e8f0",
  boxShadow:
    "0 6px 20px rgba(30,70,120,0.07)",
};

const summaryIcon = {
  width: "52px",
  height: "52px",
  borderRadius: "14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  background: "#eef4ff",
  fontSize: "24px",
};

const summaryLabel = {
  color: "#78909c",
  fontSize: "10px",
  fontWeight: "800",
  letterSpacing: "1.2px",
};

const summaryNumber = {
  color: "#3157a6",
  fontSize: "25px",
  fontWeight: "800",
  marginTop: "2px",
};

const summaryDescription = {
  marginLeft: "auto",
  maxWidth: "430px",
  color: "#718096",
  fontSize: "13px",
  lineHeight: "1.5",
};

// =====================================================
// SECCIÓN
// =====================================================

const resultsSection = {
  marginTop: "5px",
};

const sectionHeader = {
  marginBottom: "18px",
};

const sectionTitle = {
  margin: 0,
  color: "#263238",
  fontSize: "21px",
  fontWeight: "800",
};

const sectionDescription = {
  margin: "5px 0 0",
  color: "#78909c",
  fontSize: "13px",
};

// =====================================================
// GRID
// =====================================================

const resultsGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(420px, 1fr))",
  gap: "20px",
};

// =====================================================
// TARJETA RESULTADO
// =====================================================

const resultCard = {
  background: "#ffffff",
  border:
    "1px solid #e2e8f0",
  borderRadius: "18px",
  padding: "22px",
  boxShadow:
    "0 6px 20px rgba(30,70,120,0.07)",
};

const cleaverCard = {
  gridColumn: "1 / -1",
};

const resultHeader = {
  display: "flex",
  alignItems: "center",
  gap: "13px",
  marginBottom: "20px",
};

const resultNumber = {
  width: "42px",
  height: "42px",
  borderRadius: "12px",
  background:
    "linear-gradient(135deg, #5c6bc0, #3949ab)",
  color: "#ffffff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "16px",
  fontWeight: "800",
  flexShrink: 0,
};

const resultTitleContainer = {
  minWidth: 0,
};

const resultLabel = {
  color: "#90a4ae",
  fontSize: "9px",
  fontWeight: "800",
  letterSpacing: "1px",
  marginBottom: "3px",
};

const resultTitle = {
  margin: 0,
  color: "#263238",
  fontSize: "17px",
  fontWeight: "800",
};

// =====================================================
// INFO NORMAL
// =====================================================

const resultInfo = {
  display: "grid",
  gridTemplateColumns:
    "1fr 1fr",
  gap: "12px",
  marginBottom: "16px",
};

const infoBox = {
  display: "flex",
  alignItems: "center",
  gap: "10px",
  background: "#f8fafc",
  borderRadius: "12px",
  padding: "12px",
};

const infoBoxIcon = {
  width: "35px",
  height: "35px",
  borderRadius: "10px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  background: "#e8f1ff",
  fontSize: "16px",
};

const infoBoxLabel = {
  color: "#90a4ae",
  fontSize: "10px",
  fontWeight: "700",
  marginBottom: "2px",
};

const infoBoxValue = {
  color: "#263238",
  fontSize: "12px",
  fontWeight: "700",
};

const score = {
  color: "#3157a6",
  fontSize: "17px",
  fontWeight: "800",
};

// =====================================================
// CLEAVER
// =====================================================

const cleaverDate = {
  display: "flex",
  alignItems: "center",
  gap: "7px",
  color: "#718096",
  fontSize: "12px",
  fontWeight: "600",
  marginBottom: "15px",
};

const cleaverIntro = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
  background:
    "linear-gradient(135deg, #eef4ff, #f8faff)",
  border:
    "1px solid #dde7ff",
  borderRadius: "14px",
  padding: "14px",
  marginBottom: "16px",
};

const cleaverIntroIcon = {
  width: "42px",
  height: "42px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  borderRadius: "12px",
  background: "#ffffff",
  fontSize: "21px",
};

const cleaverIntroTitle = {
  color: "#3157a6",
  fontWeight: "800",
  fontSize: "15px",
};

const cleaverIntroText = {
  color: "#718096",
  fontSize: "12px",
  marginTop: "2px",
};

const cleaverPatterns = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(260px, 1fr))",
  gap: "14px",
  marginBottom: "16px",
};

const cleaverPattern = {
  border:
    "1px solid #e2e8f0",
  borderRadius: "15px",
  padding: "15px",
  background: "#fbfcff",
};

const patternHeader = {
  marginBottom: "12px",
};

const patternTitle = {
  color: "#263238",
  fontSize: "14px",
  fontWeight: "800",
};

const patternDescription = {
  color: "#90a4ae",
  fontSize: "10px",
  lineHeight: "1.4",
  marginTop: "3px",
};

const factorGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(4, minmax(55px, 1fr))",
  gap: "8px",
};

const factorBox = {
  textAlign: "center",
  background: "#ffffff",
  border:
    "1px solid #e2e8f0",
  borderRadius: "11px",
  padding: "9px 5px",
};

const factorName = {
  color: "#78909c",
  fontSize: "10px",
  fontWeight: "800",
};

const factorValue = {
  color: "#3157a6",
  fontSize: "20px",
  fontWeight: "900",
  margin: "3px 0",
};

const factorPosition = {
  color: "#90a4ae",
  fontSize: "8px",
  fontWeight: "600",
};

// =====================================================
// GRÁFICAS CLEAVER
// =====================================================

const graphsSection = {
  marginTop: "20px",
  marginBottom: "20px",
};

const graphsHeader = {
  display: "flex",
  alignItems: "center",
  justifyContent:
    "space-between",
  marginBottom: "12px",
};

const graphsTitle = {
  color: "#263238",
  fontSize: "16px",
  fontWeight: "800",
};

const graphsDescription = {
  color: "#78909c",
  fontSize: "11px",
  marginTop: "3px",
  lineHeight: "1.4",
};

const graphsGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(300px, 1fr))",
  gap: "14px",
};

const graphCard = {
  background: "#ffffff",
  border:
    "1px solid #e2e8f0",
  borderRadius: "16px",
  padding: "15px",
  boxShadow:
    "0 3px 12px rgba(30,70,120,0.04)",
  overflow: "hidden",
};

const graphHeader = {
  textAlign: "center",
  marginBottom: "4px",
};

const graphTitle = {
  fontSize: "14px",
  fontWeight: "800",
  color: "#3157a6",
};

const graphSubtitle = {
  fontSize: "9px",
  color: "#94a3b8",
  marginTop: "3px",
  minHeight: "24px",
};

const graphSvg = {
  width: "100%",
  height: "auto",
  display: "block",
};

const graphLegend = {
  textAlign: "center",
  color: "#94a3b8",
  fontSize: "9px",
  fontWeight: "600",
  marginTop: "5px",
};

// =====================================================
// PERFIL
// =====================================================

const profileBox = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
  background:
    "linear-gradient(135deg, #edf3ff, #f8faff)",
  border:
    "1px solid #dce5ff",
  borderRadius: "14px",
  padding: "15px",
  marginBottom: "15px",
};

const profileIcon = {
  width: "42px",
  height: "42px",
  borderRadius: "12px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  background: "#ffffff",
  fontSize: "20px",
  flexShrink: 0,
};

const profileLabel = {
  color: "#78909c",
  fontSize: "9px",
  fontWeight: "800",
  letterSpacing: "1px",
};

const profileValue = {
  color: "#3157a6",
  fontSize: "18px",
  fontWeight: "800",
  marginTop: "3px",
};

const cleaverWarning = {
  padding: "14px",
  borderRadius: "12px",
  background: "#fff8e8",
  color: "#9a6700",
  fontSize: "13px",
  fontWeight: "600",
};

// =====================================================
// INTERPRETACIÓN
// =====================================================

const interpretation = {
  background: "#f7f9ff",
  border:
    "1px solid #e2e8ff",
  borderRadius: "13px",
  padding: "15px",
};

const interpretationHeader = {
  display: "flex",
  alignItems: "center",
  gap: "7px",
  marginBottom: "8px",
};

const interpretationIcon = {
  fontSize: "17px",
};

const interpretationTitle = {
  color: "#3949ab",
  fontSize: "13px",
  fontWeight: "800",
};

const interpretationText = {
  margin: 0,
  color: "#546e7a",
  fontSize: "13px",
  lineHeight: "1.6",
};

// =====================================================
// SIN RESULTADOS
// =====================================================

const emptyCard = {
  background: "#ffffff",
  borderRadius: "20px",
  padding: "60px 30px",
  textAlign: "center",
  border:
    "1px solid #e2e8f0",
  boxShadow:
    "0 8px 25px rgba(30,70,120,0.07)",
};

const emptyIcon = {
  fontSize: "50px",
  marginBottom: "10px",
};

const emptyTitle = {
  margin: "0 0 8px",
  color: "#263238",
  fontSize: "21px",
};

const emptyText = {
  maxWidth: "500px",
  margin:
    "0 auto 20px",
  color: "#78909c",
  fontSize: "14px",
  lineHeight: "1.6",
};

const emptyButton = {
  border: "none",
  background:
    "linear-gradient(135deg, #5c6bc0, #3949ab)",
  color: "#ffffff",
  padding: "11px 18px",
  borderRadius: "11px",
  cursor: "pointer",
  fontWeight: "700",
};

// =====================================================
// LOADING
// =====================================================

const loadingCard = {
  maxWidth: "500px",
  margin:
    "100px auto",
  background: "#ffffff",
  padding: "45px",
  borderRadius: "20px",
  textAlign: "center",
  boxShadow:
    "0 8px 25px rgba(30,70,120,0.08)",
};

const loadingIcon = {
  fontSize: "45px",
  marginBottom: "10px",
};

const loadingTitle = {
  margin:
    "0 0 8px",
  color: "#263238",
};

const loadingText = {
  margin: 0,
  color: "#78909c",
  fontSize: "14px",
};

// =====================================================
// ERROR
// =====================================================

const errorCard = {
  maxWidth: "550px",
  margin:
    "100px auto",
  background: "#ffffff",
  padding: "45px",
  borderRadius: "20px",
  textAlign: "center",
  boxShadow:
    "0 8px 25px rgba(30,70,120,0.08)",
};

const errorIcon = {
  fontSize: "45px",
  marginBottom: "10px",
};

const errorTitle = {
  margin:
    "0 0 10px",
  color: "#263238",
};

const errorText = {
  color: "#78909c",
  marginBottom: "20px",
};

// =====================================================
// FOOTER
// =====================================================

const footer = {
  display: "flex",
  justifyContent:
    "space-between",
  borderTop:
    "1px solid #e2e8f0",
  marginTop: "35px",
  paddingTop: "18px",
  color: "#90a4ae",
  fontSize: "12px",
};