import React, {
  useCallback,
  useEffect,
  useMemo,
  useState
} from "react";

import axios from "axios";

import {
  useNavigate,
  useParams
} from "react-router-dom";


const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";


const EmpleadoDetalle = () => {

  const { idEmpleado } =
    useParams();

  const navigate =
    useNavigate();

  const token =
    localStorage.getItem("token");

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


  const [empleado, setEmpleado] =
    useState(null);

  const [cargando, setCargando] =
    useState(true);

  const [error, setError] =
    useState("");


  // ==================================================
  // CARGAR EMPLEADO
  // GET /api/empleados/:id
  // ==================================================

  const cargarEmpleado =
    useCallback(
      async () => {

        try {

          setCargando(true);
          setError("");


          console.log(
            "👔 Consultando expediente laboral:",
            `${API_URL}/api/empleados/${idEmpleado}`
          );


          const respuesta =
            await axios.get(
              `${API_URL}/api/empleados/${idEmpleado}`,
              config
            );


          console.log(
            "📦 Expediente recibido:",
            respuesta.data
          );


          const encontrado =
            respuesta.data?.empleado ||
            null;


          if (!encontrado) {

            setEmpleado(null);

            setError(
              "Empleado no encontrado o no tienes permiso para acceder a él."
            );

            return;

          }


          setEmpleado(
            encontrado
          );


        } catch (err) {

          console.error(
            "❌ Error cargando empleado RH:",
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


          setEmpleado(null);


          setError(
            err.response?.data?.message ||
            err.response?.data?.error ||
            "No fue posible cargar el expediente laboral."
          );


        } finally {

          setCargando(false);

        }

      },
      [
        idEmpleado,
        config
      ]
    );


  useEffect(
    () => {
      cargarEmpleado();
    },
    [cargarEmpleado]
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
  // ABRIR HISTORIAL DE SELECCIÓN
  // ==================================================

  const abrirProcesoSeleccion =
    () => {

      if (
        !empleado?.id_prospecto
      ) {
        return;
      }


      navigate(
        `/prospecto/${empleado.id_prospecto}`
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
              👔 Expediente laboral
            </h2>

            <p>
              Cargando información...
            </p>

          </div>

        </div>

      </div>

    );

  }


  // ==================================================
  // ERROR
  // ==================================================

  if (
    error ||
    !empleado
  ) {

    return (

      <div style={styles.page}>

        <div style={styles.container}>

          <button
            type="button"
            style={styles.backButton}
            onClick={() =>
              navigate(
                "/empleados"
              )
            }
          >
            ← Volver a empleados
          </button>


          <div style={styles.card}>

            <div style={styles.empty}>

              <div style={styles.emptyIcon}>
                ⚠️
              </div>

              <h2>
                No se pudo abrir el expediente
              </h2>

              <p>
                {
                  error ||
                  "Empleado no encontrado."
                }
              </p>

            </div>

          </div>

        </div>

      </div>

    );

  }


  const estado =
    obtenerEstatus(
      empleado.estatus
    );


  return (

    <div style={styles.page}>

      <div style={styles.container}>


        {/* ==========================================
            VOLVER
        ========================================== */}

        <button
          type="button"
          style={styles.backButton}
          onClick={() =>
            navigate(
              "/empleados"
            )
          }
        >
          ← Volver a empleados
        </button>


        {/* ==========================================
            CABECERA
        ========================================== */}

        <div style={styles.headerCard}>

          <div style={styles.employeeHeader}>

            <div style={styles.avatar}>

              {
                empleado.nombre
                  ?.charAt(0)
                  ?.toUpperCase() ||
                "E"
              }

            </div>


            <div style={styles.headerInfo}>

              <div style={styles.nameRow}>

                <h1 style={styles.title}>
                  {empleado.nombre}
                </h1>


                <span
                  style={{
                    ...styles.statusBadge,
                    background:
                      estado.fondo,
                    color:
                      estado.color
                  }}
                >
                  {estado.texto}
                </span>

              </div>


              <div style={styles.mirrorId}>

                🆔{" "}

                {
                  empleado.id_mirror ||
                  "Sin ID MirrorSoul"
                }

              </div>


              <div style={styles.position}>

                💼{" "}

                {
                  empleado.puesto ||
                  "Puesto no especificado"
                }

              </div>

            </div>

          </div>


          <div style={styles.headerActions}>

            {empleado.id_prospecto && (

              <button
                type="button"
                style={styles.secondaryButton}
                onClick={
                  abrirProcesoSeleccion
                }
              >
                📋 Ver proceso de selección
              </button>

            )}

          </div>

        </div>


        {/* ==========================================
            INFORMACIÓN LABORAL
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                👔 Información laboral
              </h2>

              <p style={styles.cardSubtitle}>
                Información actual del empleado.
              </p>

            </div>

          </div>


          <div style={styles.infoGrid}>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                Puesto
              </span>

              <strong>
                {
                  empleado.puesto ||
                  "No especificado"
                }
              </strong>

            </div>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                Departamento
              </span>

              <strong>
                {
                  empleado.departamento ||
                  "No especificado"
                }
              </strong>

            </div>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                Fecha de contratación
              </span>

              <strong>

                {
                  formatearFecha(
                    empleado.fecha_contratacion
                  )
                }

              </strong>

            </div>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                Estado laboral
              </span>

              <strong>
                {estado.texto}
              </strong>

            </div>

          </div>

        </div>


        {/* ==========================================
            DATOS PERSONALES
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                👤 Datos generales
              </h2>

              <p style={styles.cardSubtitle}>
                Información identificativa del
                empleado.
              </p>

            </div>

          </div>


          <div style={styles.infoGrid}>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                ID MirrorSoul
              </span>

              <strong>
                {
                  empleado.id_mirror ||
                  "No asignado"
                }
              </strong>

            </div>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
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


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
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


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                Correo
              </span>

              <strong style={styles.breakText}>
                {
                  empleado.correo ||
                  "No registrado"
                }
              </strong>

            </div>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                Teléfono
              </span>

              <strong>
                {
                  empleado.telefono ||
                  "No registrado"
                }
              </strong>

            </div>


            <div style={styles.infoItem}>

              <span style={styles.infoLabel}>
                Dirección
              </span>

              <strong>
                {
                  empleado.direccion ||
                  "No registrada"
                }
              </strong>

            </div>

          </div>

        </div>


        {/* ==========================================
            ANTECEDENTES DE SELECCIÓN
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                📂 Antecedentes de selección
              </h2>

              <p style={styles.cardSubtitle}>
                El proceso anterior permanece
                vinculado como antecedente del
                expediente laboral.
              </p>

            </div>

          </div>


          {empleado.id_prospecto ? (

            <>

              <div style={styles.continuityBox}>

                <strong>
                  🔗 Expediente vinculado
                </strong>

                <p style={styles.continuityText}>
                  Este empleado proviene del
                  proceso de selección registrado
                  en MirrorSoul. Las entrevistas,
                  pruebas psicométricas,
                  seguimientos, observaciones y
                  decisiones permanecen en su
                  expediente de prospecto.
                </p>

              </div>


              <button
                type="button"
                style={styles.secondaryButton}
                onClick={
                  abrirProcesoSeleccion
                }
              >
                Abrir expediente de selección →
              </button>

            </>

          ) : (

            <div style={styles.empty}>

              <p>
                No existe un proceso de selección
                vinculado.
              </p>

            </div>

          )}

        </div>


        {/* ==========================================
            MÓDULOS DEL EMPLEADO
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                🧩 Seguimiento del empleado
              </h2>

              <p style={styles.cardSubtitle}>
                Herramientas para prevención,
                seguimiento laboral y bienestar.
              </p>

            </div>

          </div>


          <div style={styles.moduleGrid}>


            {/* SEGUIMIENTO */}

            <button
              type="button"
              style={styles.moduleCard}
              onClick={() =>
                navigate(
                  `/empleado/${idEmpleado}/seguimiento`
                )
              }
            >

              <div style={styles.moduleIcon}>
                📈
              </div>

              <h3>
                Seguimiento laboral
              </h3>

              <p>
                Registra evolución, situaciones
                relevantes, acuerdos y acciones
                de seguimiento.
              </p>

            </button>


            {/* EVALUACIONES */}

            <button
              type="button"
              style={styles.moduleCard}
              onClick={() =>
                navigate(
                  `/empleado/${idEmpleado}/evaluaciones`
                )
              }
            >

              <div style={styles.moduleIcon}>
                🧠
              </div>

              <h3>
                Evaluaciones periódicas
              </h3>

              <p>
                Aplica evaluaciones de
                seguimiento y prevención durante
                la relación laboral.
              </p>

            </button>


            {/* BIENESTAR */}

            <button
              type="button"
              style={styles.moduleCard}
              onClick={() =>
                navigate(
                  `/empleado/${idEmpleado}/bienestar`
                )
              }
            >

              <div style={styles.moduleIcon}>
                🌿
              </div>

              <h3>
                Bienestar y prevención
              </h3>

              <p>
                Consulta indicadores laborales
                y registra acciones preventivas.
              </p>

            </button>


            {/* NOM-035 */}

            <button
              type="button"
              style={styles.moduleCard}
              onClick={() =>
                navigate(
                  `/empleado/${idEmpleado}/nom035`
                )
              }
            >

              <div style={styles.moduleIcon}>
                📋
              </div>

              <h3>
                NOM-035
              </h3>

              <p>
                Módulo para seguimiento de
                factores de riesgo psicosocial
                relacionados con el trabajo.
              </p>

              <span style={styles.pendingBadge}>
                Próximamente
              </span>

            </button>


            {/* CANALIZACIÓN */}

            <button
              type="button"
              style={styles.moduleCard}
              onClick={() =>
                navigate(
                  `/empleado/${idEmpleado}/canalizacion`
                )
              }
            >

              <div style={styles.moduleIcon}>
                🤝
              </div>

              <h3>
                Canalización
              </h3>

              <p>
                Facilita opciones de apoyo
                profesional cuando se detecten
                indicadores que requieran
                atención especializada.
              </p>

              <span style={styles.pendingBadge}>
                Próximamente
              </span>

            </button>

          </div>

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
    background: "#f6f8fb",
    padding: "30px 20px"
  },

  container: {
    maxWidth: "1180px",
    margin: "0 auto"
  },

  backButton: {
    border: "none",
    background: "transparent",
    padding: 0,
    marginBottom: "14px",
    cursor: "pointer",
    color: "#344054",
    fontWeight: "700"
  },

  headerCard: {
    background: "#ffffff",
    borderRadius: "18px",
    padding: "24px",
    marginBottom: "22px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    flexWrap: "wrap",
    gap: "20px"
  },

  employeeHeader: {
    display: "flex",
    alignItems: "center",
    gap: "17px"
  },

  avatar: {
    width: "68px",
    height: "68px",
    minWidth: "68px",
    borderRadius: "50%",
    background: "#e8eef9",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "29px",
    fontWeight: "800"
  },

  headerInfo: {
    minWidth: 0
  },

  nameRow: {
    display: "flex",
    alignItems: "center",
    flexWrap: "wrap",
    gap: "10px"
  },

  title: {
    margin: 0,
    fontSize: "29px"
  },

  statusBadge: {
    borderRadius: "20px",
    padding: "5px 10px",
    fontSize: "12px",
    fontWeight: "700"
  },

  mirrorId: {
    color: "#667085",
    marginTop: "6px"
  },

  position: {
    color: "#344054",
    marginTop: "5px",
    fontWeight: "600"
  },

  headerActions: {
    display: "flex",
    gap: "10px"
  },

  card: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "24px",
    marginBottom: "22px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  cardHeader: {
    marginBottom: "20px"
  },

  cardTitle: {
    margin: "0 0 5px"
  },

  cardSubtitle: {
    margin: 0,
    color: "#667085"
  },

  infoGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(210px, 1fr))",
    gap: "18px"
  },

  infoItem: {
    padding: "14px",
    background: "#f8fafc",
    borderRadius: "10px",
    minWidth: 0,
    display: "flex",
    flexDirection: "column",
    gap: "5px"
  },

  infoLabel: {
    color: "#667085",
    fontSize: "12px"
  },

  breakText: {
    wordBreak: "break-word"
  },

  continuityBox: {
    border: "1px solid #dbeafe",
    background: "#eff6ff",
    borderRadius: "12px",
    padding: "16px",
    marginBottom: "14px",
    color: "#1e3a8a"
  },

  continuityText: {
    margin: "7px 0 0",
    lineHeight: 1.5
  },

  secondaryButton: {
    border: "1px solid #d0d5dd",
    background: "#ffffff",
    borderRadius: "10px",
    padding: "10px 15px",
    cursor: "pointer",
    fontWeight: "700"
  },

  moduleGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(230px, 1fr))",
    gap: "16px"
  },

  moduleCard: {
    position: "relative",
    textAlign: "left",
    border: "1px solid #e4e7ec",
    background: "#ffffff",
    borderRadius: "14px",
    padding: "20px",
    cursor: "pointer",
    minHeight: "190px"
  },

  moduleIcon: {
    fontSize: "31px",
    marginBottom: "8px"
  },

  pendingBadge: {
    display: "inline-block",
    marginTop: "7px",
    background: "#f2f4f7",
    color: "#667085",
    borderRadius: "20px",
    padding: "4px 8px",
    fontSize: "11px",
    fontWeight: "700"
  },

  empty: {
    textAlign: "center",
    padding: "30px",
    color: "#667085"
  },

  emptyIcon: {
    fontSize: "38px"
  }

};


export default EmpleadoDetalle;