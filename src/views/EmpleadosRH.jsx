// src/views/EmpleadosRH.jsx

import React, {
  useCallback,
  useEffect,
  useMemo,
  useState
} from "react";

import axios from "axios";

import {
  useNavigate
} from "react-router-dom";

import {
  getToken,
  clearSession
} from "../services/AuthService";

// ==================================================
// API
// ==================================================

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

// ==================================================
// COMPONENTE
// ==================================================

const EmpleadosRH = () => {
  const navigate =
    useNavigate();

  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    empleados,
    setEmpleados
  ] = useState([]);

  const [
    busqueda,
    setBusqueda
  ] = useState("");

  const [
    cargando,
    setCargando
  ] = useState(true);

  const [
    error,
    setError
  ] = useState("");

  // ==================================================
  // TOKEN ACTUAL
  // ==================================================

  const token =
    getToken();

  // ==================================================
  // CONFIGURACIÓN AXIOS
  // ==================================================

  const config =
    useMemo(
      () => ({
        headers: {
          Authorization:
            `Bearer ${token}`
        }
      }),
      [token]
    );

  // ==================================================
  // CARGAR EMPLEADOS
  // ==================================================

  const cargarEmpleados =
    useCallback(
      async () => {
        try {
          setCargando(true);
          setError("");

          // =========================================
          // VALIDAR SESIÓN
          // =========================================

          const tokenActual =
            getToken();

          console.log(
            "🔐 Token EmpleadosRH:",
            tokenActual
              ? "Existe"
              : "NO existe"
          );

          if (!tokenActual) {
            clearSession();

            navigate(
              "/login",
              {
                replace: true
              }
            );

            return;
          }

          console.log(
            "👔 Consultando empleados:",
            `${API_URL}/api/empleados`
          );

          // =========================================
          // PETICIÓN
          // =========================================

          const respuesta =
            await axios.get(
              `${API_URL}/api/empleados`,
              {
                headers: {
                  Authorization:
                    `Bearer ${tokenActual}`
                }
              }
            );

          console.log(
            "📦 Empleados recibidos:",
            respuesta.data
          );

          // =========================================
          // NORMALIZAR RESPUESTA
          // =========================================

          const lista =
            Array.isArray(
              respuesta.data?.empleados
            )
              ? respuesta.data.empleados
              : Array.isArray(
                  respuesta.data
                )
              ? respuesta.data
              : [];

          setEmpleados(
            lista
          );
        } catch (err) {
          console.error(
            "❌ Error cargando empleados RH:",
            err
          );

          console.error(
            "📦 Respuesta backend:",
            err.response?.data
          );

          console.error(
            "📡 Status:",
            err.response?.status
          );

          setEmpleados([]);

          // =========================================
          // TOKEN INVÁLIDO / EXPIRADO
          // =========================================

          if (
            err.response?.status ===
            401
          ) {
            clearSession();

            navigate(
              "/login",
              {
                replace: true
              }
            );

            return;
          }

          // =========================================
          // SIN PERMISO
          // =========================================

          if (
            err.response?.status ===
            403
          ) {
            setError(
              err.response?.data?.message ||
              "No tienes permiso para consultar empleados."
            );

            return;
          }

          // =========================================
          // OTROS ERRORES
          // =========================================

          setError(
            err.response?.data?.message ||
            err.response?.data?.error ||
            "No fue posible cargar los empleados."
          );
        } finally {
          setCargando(false);
        }
      },
      [
        navigate
      ]
    );

  // ==================================================
  // CARGAR AL ENTRAR
  // ==================================================

  useEffect(
    () => {
      cargarEmpleados();
    },
    [cargarEmpleados]
  );

  // ==================================================
  // FILTRAR EMPLEADOS
  // ==================================================

  const empleadosFiltrados =
    useMemo(
      () => {
        const texto =
          String(
            busqueda || ""
          )
            .trim()
            .toLowerCase();

        if (!texto) {
          return empleados;
        }

        return empleados.filter(
          empleado => {
            const valores = [
              empleado.nombre,
              empleado.id_mirror,
              empleado.correo,
              empleado.telefono,
              empleado.puesto,
              empleado.departamento,
              empleado.estatus
            ];

            return valores.some(
              valor =>
                String(
                  valor || ""
                )
                  .toLowerCase()
                  .includes(
                    texto
                  )
            );
          }
        );
      },
      [
        empleados,
        busqueda
      ]
    );

  // ==================================================
  // FORMATEAR FECHA
  // ==================================================

  const formatearFecha =
    fecha => {
      if (!fecha) {
        return "No registrada";
      }

      const date =
        new Date(
          fecha
        );

      if (
        Number.isNaN(
          date.getTime()
        )
      ) {
        return fecha;
      }

      return date.toLocaleDateString(
        "es-MX",
        {
          year: "numeric",
          month: "long",
          day: "numeric"
        }
      );
    };

  // ==================================================
  // SEXO
  // ==================================================

  const textoSexo =
    sexo => {
      if (sexo === "F") {
        return "Femenino";
      }

      if (sexo === "M") {
        return "Masculino";
      }

      return "No especificado";
    };

  // ==================================================
  // ESTATUS
  // ==================================================

  const obtenerEstatus =
    estatus => {
      const estados = {
        activo: {
          texto: "Activo",
          fondo: "#ecfdf3",
          color: "#067647"
        },

        inactivo: {
          texto: "Inactivo",
          fondo: "#f2f4f7",
          color: "#475467"
        },

        baja: {
          texto: "Baja",
          fondo: "#fef3f2",
          color: "#b42318"
        }
      };

      return (
        estados[
          String(
            estatus || ""
          ).toLowerCase()
        ] ||
        estados.inactivo
      );
    };

  // ==================================================
  // ABRIR EXPEDIENTE
  // ==================================================

  const abrirEmpleado =
    empleado => {
      navigate(
        `/empleado/${empleado.id_empleado}`
      );
    };

  // ==================================================
  // VOLVER AL DASHBOARD RH
  // ==================================================

  const volverDashboard =
    () => {
      navigate(
        "/dashboard",
        {
          replace: true
        }
      );
    };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.container}>
          <div style={styles.card}>
            <h2>
              👔 Empleados RH
            </h2>

            <p>
              Cargando empleados...
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ==================================================
  // RENDER
  // ==================================================

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* ==========================================
            VOLVER AL PANEL RH
        ========================================== */}

        <button
          type="button"
          style={
            styles.backButton
          }
          onClick={
            volverDashboard
          }
        >
          ← Volver al panel RH
        </button>

        {/* ==========================================
            ENCABEZADO
        ========================================== */}

        <div style={styles.header}>
          <div>
            <h1
              style={
                styles.title
              }
            >
              👔 Empleados
            </h1>

            <p
              style={
                styles.subtitle
              }
            >
              Consulta y administra los empleados que fueron incorporados desde el proceso de selección.
            </p>
          </div>
        </div>

        {/* ==========================================
            ERROR
        ========================================== */}

        {error && (
          <div
            style={
              styles.error
            }
          >
            ❌ {error}
          </div>
        )}

        {/* ==========================================
            RESUMEN
        ========================================== */}

        <div
          style={
            styles.summaryGrid
          }
        >
          <div
            style={
              styles.summaryCard
            }
          >
            <div
              style={
                styles.summaryIcon
              }
            >
              👥
            </div>

            <div>
              <div
                style={
                  styles.summaryNumber
                }
              >
                {
                  empleados.length
                }
              </div>

              <div
                style={
                  styles.summaryLabel
                }
              >
                Empleados registrados
              </div>
            </div>
          </div>

          <div
            style={
              styles.summaryCard
            }
          >
            <div
              style={
                styles.summaryIcon
              }
            >
              ✅
            </div>

            <div>
              <div
                style={
                  styles.summaryNumber
                }
              >
                {
                  empleados.filter(
                    empleado =>
                      empleado.estatus ===
                      "activo"
                  ).length
                }
              </div>

              <div
                style={
                  styles.summaryLabel
                }
              >
                Empleados activos
              </div>
            </div>
          </div>
        </div>

        {/* ==========================================
            BUSCADOR
        ========================================== */}

        <div
          style={
            styles.card
          }
        >
          <div
            style={
              styles.searchRow
            }
          >
            <div
              style={
                styles.searchBox
              }
            >
              <span
                style={
                  styles.searchIcon
                }
              >
                🔎
              </span>

              <input
                type="text"
                placeholder="Buscar por nombre, ID MirrorSoul, puesto, departamento..."
                value={
                  busqueda
                }
                onChange={
                  e =>
                    setBusqueda(
                      e.target.value
                    )
                }
                style={
                  styles.searchInput
                }
              />
            </div>

            <div
              style={
                styles.counter
              }
            >
              {
                empleadosFiltrados.length
              }
            </div>
          </div>
        </div>

        {/* ==========================================
            LISTA
        ========================================== */}

        <div
          style={
            styles.card
          }
        >
          <div
            style={
              styles.cardHeader
            }
          >
            <div>
              <h2
                style={
                  styles.cardTitle
                }
              >
                📋 Empleados registrados
              </h2>

              <p
                style={
                  styles.cardSubtitle
                }
              >
                Cada empleado conserva su historial del proceso de selección.
              </p>
            </div>
          </div>

          {empleadosFiltrados.length ===
          0 ? (
            <div
              style={
                styles.empty
              }
            >
              <div
                style={
                  styles.emptyIcon
                }
              >
                👔
              </div>

              <h3>
                {
                  busqueda
                    ? "No se encontraron empleados"
                    : "Todavía no hay empleados"
                }
              </h3>

              <p>
                {
                  busqueda
                    ? "Intenta con otro término de búsqueda."
                    : "Cuando un prospecto sea contratado aparecerá aquí automáticamente."
                }
              </p>
            </div>
          ) : (
            <div
              style={
                styles.grid
              }
            >
              {empleadosFiltrados.map(
                empleado => {
                  const estado =
                    obtenerEstatus(
                      empleado.estatus
                    );

                  return (
                    <div
                      key={
                        empleado.id_empleado
                      }
                      style={
                        styles.employeeCard
                      }
                    >
                      <div
                        style={
                          styles.employeeTop
                        }
                      >
                        <div
                          style={
                            styles.avatar
                          }
                        >
                          {
                            empleado.nombre
                              ?.charAt(0)
                              ?.toUpperCase() ||
                            "E"
                          }
                        </div>

                        <div
                          style={
                            styles.employeeTitleBox
                          }
                        >
                          <h3
                            style={
                              styles.employeeName
                            }
                          >
                            {
                              empleado.nombre
                            }
                          </h3>

                          <div
                            style={
                              styles.mirrorId
                            }
                          >
                            🆔{" "}
                            {
                              empleado.id_mirror ||
                              "Sin ID MirrorSoul"
                            }
                          </div>
                        </div>

                        <span
                          style={{
                            ...styles.statusBadge,
                            background:
                              estado.fondo,
                            color:
                              estado.color
                          }}
                        >
                          {
                            estado.texto
                          }
                        </span>
                      </div>

                      <div
                        style={
                          styles.infoGrid
                        }
                      >
                        <div
                          style={
                            styles.infoItem
                          }
                        >
                          <span
                            style={
                              styles.infoLabel
                            }
                          >
                            Puesto
                          </span>

                          <strong>
                            {
                              empleado.puesto ||
                              "No especificado"
                            }
                          </strong>
                        </div>

                        <div
                          style={
                            styles.infoItem
                          }
                        >
                          <span
                            style={
                              styles.infoLabel
                            }
                          >
                            Departamento
                          </span>

                          <strong>
                            {
                              empleado.departamento ||
                              "No especificado"
                            }
                          </strong>
                        </div>

                        <div
                          style={
                            styles.infoItem
                          }
                        >
                          <span
                            style={
                              styles.infoLabel
                            }
                          >
                            Edad
                          </span>

                          <strong>
                            {
                              empleado.edad
                                ? `${empleado.edad} años`
                                : "No registrada"
                            }
                          </strong>
                        </div>

                        <div
                          style={
                            styles.infoItem
                          }
                        >
                          <span
                            style={
                              styles.infoLabel
                            }
                          >
                            Sexo
                          </span>

                          <strong>
                            {
                              textoSexo(
                                empleado.sexo
                              )
                            }
                          </strong>
                        </div>

                        <div
                          style={
                            styles.infoItem
                          }
                        >
                          <span
                            style={
                              styles.infoLabel
                            }
                          >
                            Contratación
                          </span>

                          <strong>
                            {
                              formatearFecha(
                                empleado.fecha_contratacion
                              )
                            }
                          </strong>
                        </div>

                        <div
                          style={
                            styles.infoItem
                          }
                        >
                          <span
                            style={
                              styles.infoLabel
                            }
                          >
                            Correo
                          </span>

                          <strong
                            style={
                              styles.breakText
                            }
                          >
                            {
                              empleado.correo ||
                              "No registrado"
                            }
                          </strong>
                        </div>
                      </div>

                      {empleado.id_prospecto && (
                        <div
                          style={
                            styles.historyNotice
                          }
                        >
                          <strong>
                            🔗 Historial de selección vinculado
                          </strong>

                          <p
                            style={
                              styles.noticeText
                            }
                          >
                            Este empleado conserva entrevistas, pruebas, seguimiento, observaciones y decisiones realizadas durante su etapa como prospecto.
                          </p>
                        </div>
                      )}

                      <button
                        type="button"
                        style={
                          styles.primaryButton
                        }
                        onClick={() =>
                          abrirEmpleado(
                            empleado
                          )
                        }
                      >
                        Ver expediente laboral →
                      </button>
                    </div>
                  );
                }
              )}
            </div>
          )}
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
    minHeight:
      "100vh",

    background:
      "#f6f8fb",

    padding:
      "30px 20px"
  },

  container: {
    maxWidth:
      "1200px",

    margin:
      "0 auto"
  },

  backButton: {
    position:
      "relative",

    zIndex:
      99999,

    pointerEvents:
      "auto",

    display:
      "inline-block",

    border:
      "none",

    background:
      "transparent",

    padding:
      "6px 0",

    marginBottom:
      "14px",

    cursor:
      "pointer",

    color:
      "#344054",

    fontWeight:
      "700",

    fontSize:
      "14px"
  },

  header: {
    marginBottom:
      "22px"
  },

  title: {
    margin:
      "0 0 6px",

    fontSize:
      "30px"
  },

  subtitle: {
    margin:
      0,

    color:
      "#667085",

    maxWidth:
      "700px"
  },

  card: {
    background:
      "#ffffff",

    borderRadius:
      "16px",

    padding:
      "24px",

    marginBottom:
      "22px",

    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  error: {
    background:
      "#fef3f2",

    border:
      "1px solid #fecdca",

    borderRadius:
      "10px",

    padding:
      "13px",

    marginBottom:
      "18px"
  },

  summaryGrid: {
    display:
      "grid",

    gridTemplateColumns:
      "repeat(auto-fit, minmax(230px, 1fr))",

    gap:
      "16px",

    marginBottom:
      "22px"
  },

  summaryCard: {
    background:
      "#ffffff",

    borderRadius:
      "14px",

    padding:
      "20px",

    display:
      "flex",

    alignItems:
      "center",

    gap:
      "14px",

    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  summaryIcon: {
    width:
      "52px",

    height:
      "52px",

    borderRadius:
      "14px",

    background:
      "#eef2f7",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    fontSize:
      "25px"
  },

  summaryNumber: {
    fontSize:
      "27px",

    fontWeight:
      "800"
  },

  summaryLabel: {
    color:
      "#667085",

    fontSize:
      "14px"
  },

  searchRow: {
    display:
      "flex",

    alignItems:
      "center",

    gap:
      "15px"
  },

  searchBox: {
    flex:
      1,

    display:
      "flex",

    alignItems:
      "center",

    border:
      "1px solid #d0d5dd",

    borderRadius:
      "10px",

    padding:
      "0 12px"
  },

  searchIcon: {
    marginRight:
      "8px"
  },

  searchInput: {
    flex:
      1,

    border:
      "none",

    outline:
      "none",

    padding:
      "12px 0",

    fontSize:
      "15px"
  },

  counter: {
    minWidth:
      "42px",

    height:
      "42px",

    borderRadius:
      "10px",

    background:
      "#eef2f7",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    fontWeight:
      "700"
  },

  cardHeader: {
    marginBottom:
      "20px"
  },

  cardTitle: {
    margin:
      "0 0 5px"
  },

  cardSubtitle: {
    margin:
      0,

    color:
      "#667085"
  },

  grid: {
    display:
      "grid",

    gridTemplateColumns:
      "repeat(auto-fit, minmax(330px, 1fr))",

    gap:
      "18px"
  },

  employeeCard: {
    border:
      "1px solid #e4e7ec",

    borderRadius:
      "15px",

    padding:
      "20px",

    display:
      "flex",

    flexDirection:
      "column"
  },

  employeeTop: {
    display:
      "flex",

    alignItems:
      "center",

    gap:
      "12px",

    marginBottom:
      "18px"
  },

  avatar: {
    width:
      "52px",

    height:
      "52px",

    minWidth:
      "52px",

    borderRadius:
      "50%",

    background:
      "#e8eef9",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    fontSize:
      "23px",

    fontWeight:
      "800"
  },

  employeeTitleBox: {
    flex:
      1,

    minWidth:
      0
  },

  employeeName: {
    margin:
      "0 0 5px",

    fontSize:
      "19px"
  },

  mirrorId: {
    color:
      "#667085",

    fontSize:
      "13px"
  },

  statusBadge: {
    borderRadius:
      "20px",

    padding:
      "5px 9px",

    fontSize:
      "12px",

    fontWeight:
      "700"
  },

  infoGrid: {
    display:
      "grid",

    gridTemplateColumns:
      "repeat(2, minmax(0, 1fr))",

    gap:
      "14px",

    marginBottom:
      "18px"
  },

  infoItem: {
    minWidth:
      0,

    display:
      "flex",

    flexDirection:
      "column",

    gap:
      "4px"
  },

  infoLabel: {
    color:
      "#667085",

    fontSize:
      "12px"
  },

  breakText: {
    wordBreak:
      "break-word"
  },

  historyNotice: {
    background:
      "#f8fafc",

    border:
      "1px solid #e4e7ec",

    borderRadius:
      "10px",

    padding:
      "13px",

    marginBottom:
      "16px"
  },

  noticeText: {
    color:
      "#667085",

    lineHeight:
      1.5,

    margin:
      "6px 0 0",

    fontSize:
      "13px"
  },

  primaryButton: {
    width:
      "100%",

    border:
      "none",

    borderRadius:
      "10px",

    background:
      "#2563eb",

    color:
      "#ffffff",

    padding:
      "11px 15px",

    cursor:
      "pointer",

    fontWeight:
      "700",

    marginTop:
      "auto"
  },

  empty: {
    textAlign:
      "center",

    padding:
      "38px",

    color:
      "#667085"
  },

  emptyIcon: {
    fontSize:
      "42px"
  }
};

export default EmpleadosRH;