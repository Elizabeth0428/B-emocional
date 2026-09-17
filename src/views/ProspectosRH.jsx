// ==================================================
// src/views/ProspectosRH.jsx
// ==================================================

import React, { useEffect, useState } from "react";

// ==================================================
// API
// ==================================================

const API_URL =
  import.meta.env.VITE_API_URL || "http://localhost:5000";

// ==================================================
// COMPONENTE
// ==================================================

const ProspectosRH = ({ onBack, onNavigate }) => {

  // ==================================================
  // ESTADOS
  // ==================================================

  const [prospectos, setProspectos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busqueda, setBusqueda] = useState("");

  // ==================================================
  // CARGAR PROSPECTOS
  // ==================================================

  const cargarProspectos = async () => {
    try {
      setLoading(true);
      setError("");

      const token = localStorage.getItem("token");

      if (!token) {
        throw new Error(
          "No hay sesión activa. Vuelve a iniciar sesión."
        );
      }

      console.log("🔎 Consultando prospectos...");
      console.log(
        "🌐 URL:",
        `${API_URL}/api/prospectos`
      );

      const response = await fetch(
        `${API_URL}/api/prospectos`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      const data = await response.json();

      console.log("📦 Respuesta:", data);
      console.log("📡 Status:", response.status);

      if (!response.ok) {
        throw new Error(
          data?.message ||
            `Error HTTP ${response.status}`
        );
      }

      let lista = [];

      if (Array.isArray(data)) {
        lista = data;
      } else if (Array.isArray(data?.prospectos)) {
        lista = data.prospectos;
      } else if (Array.isArray(data?.data)) {
        lista = data.data;
      }

      console.log(
        "👥 Prospectos encontrados:",
        lista.length
      );

      console.log("📋 Lista:", lista);

      setProspectos(lista);

    } catch (err) {
      console.error(
        "❌ Error al cargar prospectos:",
        err
      );

      setProspectos([]);

      setError(
        err?.message ||
          "No se pudieron cargar los prospectos."
      );

    } finally {
      setLoading(false);
    }
  };

  // ==================================================
  // CARGAR AL ENTRAR
  // ==================================================

  useEffect(() => {
    cargarProspectos();
  }, []);

  // ==================================================
  // BUSCADOR
  // ==================================================

  const prospectosFiltrados = prospectos.filter(
    (prospecto) => {

      const texto = busqueda
        .toLowerCase()
        .trim();

      if (!texto) {
        return true;
      }

      return (
        String(
          prospecto?.nombre || ""
        )
          .toLowerCase()
          .includes(texto) ||

        String(
          prospecto?.correo || ""
        )
          .toLowerCase()
          .includes(texto) ||

        String(
          prospecto?.puesto || ""
        )
          .toLowerCase()
          .includes(texto) ||

        String(
          prospecto?.telefono || ""
        )
          .toLowerCase()
          .includes(texto) ||

        String(
          prospecto?.id_mirror ||
            prospecto?.mirror_id ||
            prospecto?.codigo ||
            ""
        )
          .toLowerCase()
          .includes(texto) ||

        String(
          prospecto?.estatus ||
            prospecto?.estado ||
            ""
        )
          .toLowerCase()
          .includes(texto)
      );
    }
  );

  // ==================================================
  // OBTENER ESTADO
  // ==================================================

  const obtenerEstado = (prospecto) => {

    const estado = String(
      prospecto?.estatus ||
        prospecto?.estado ||
        "prospecto"
    )
      .trim()
      .toLowerCase();

    const estados = {

      prospecto: {
        texto: "Prospecto",
        fondo: "#FFF7E6",
        color: "#B7791F",
      },

      en_proceso: {
        texto: "En proceso",
        fondo: "#EEF4FF",
        color: "#2167D5",
      },

      evaluacion: {
        texto: "En evaluación",
        fondo: "#F3E9FF",
        color: "#7540D5",
      },

      aprobado: {
        texto: "Aprobado",
        fondo: "#ECF9EF",
        color: "#3BAE55",
      },

      contratado: {
        texto: "Contratado",
        fondo: "#E8F8ED",
        color: "#27843A",
      },

      no_contratado: {
        texto: "No contratado",
        fondo: "#FFF1F1",
        color: "#C62828",
      },

    };

    return (
      estados[estado] ||
      estados.prospecto
    );
  };

  // ==================================================
  // NAVEGACIÓN
  // ==================================================

  const abrirDetalle = (prospecto) => {

    if (typeof onNavigate === "function") {
      onNavigate(
        "detalleProspecto",
        prospecto
      );
    }
  };

  const abrirSeguimiento = (prospecto) => {

    if (typeof onNavigate === "function") {
      onNavigate(
        "seguimientoProspecto",
        prospecto
      );
    }
  };

  // ==================================================
  // DATOS DEL PROSPECTO
  // ==================================================

  const obtenerIdMirror = (prospecto) => {

    return (
      prospecto?.id_mirror ||
      prospecto?.mirror_id ||
      prospecto?.codigo ||
      null
    );
  };

  const obtenerNombre = (prospecto) => {

    return (
      prospecto?.nombre ||
      "Prospecto sin nombre"
    );
  };

  const obtenerInicial = (prospecto) => {

    const nombre =
      obtenerNombre(prospecto);

    return nombre
      .trim()
      .charAt(0)
      .toUpperCase();
  };

  const obtenerSexo = (prospecto) => {

    return (
      prospecto?.sexo ||
      prospecto?.genero ||
      "No especificado"
    );
  };

  const obtenerEdad = (prospecto) => {

    if (
      prospecto?.edad !== undefined &&
      prospecto?.edad !== null &&
      prospecto?.edad !== ""
    ) {
      return `${prospecto.edad} años`;
    }

    return "No especificada";
  };

  // ==================================================
  // RENDER
  // ==================================================

  return (
    <div style={container}>

      {/* ==================================================
          ENCABEZADO
      ================================================== */}

      <div style={header}>

        <div style={headerLeft}>

          <div style={brand}>
            MIRRORSOUL
          </div>

          <h1 style={title}>
            <span style={titleIcon}>👥</span>
            Prospectos
          </h1>

          <p style={subtitle}>
            Consulta los prospectos y accede a su expediente
            para revisar todo su proceso de selección.
          </p>

        </div>

        {/* ==============================================
            CONTADOR
        ============================================== */}

        <div style={countBox}>

          <div style={countNumber}>
            {prospectos.length}
          </div>

          <div style={countLabel}>
            prospectos
          </div>

        </div>

      </div>

      {/* ==================================================
          BUSCADOR
      ================================================== */}

      <div style={searchBox}>

        <span style={searchIcon}>
          🔎
        </span>

        <input
          type="text"
          value={busqueda}
          onChange={(e) =>
            setBusqueda(e.target.value)
          }
          placeholder="Buscar por nombre, correo, puesto o ID..."
          style={searchInput}
        />

      </div>

      {/* ==================================================
          CONTADOR DE RESULTADOS
      ================================================== */}

      {!loading && !error && (
        <div style={counter}>

          Mostrando{" "}

          <strong>
            {prospectosFiltrados.length}
          </strong>

          {prospectosFiltrados.length === 1
            ? " prospecto"
            : " prospectos"}

        </div>
      )}

      {/* ==================================================
          CARGANDO
      ================================================== */}

      {loading && (

        <div style={empty}>

          <div style={loadingIcon}>
            ⏳
          </div>

          <h3 style={emptyTitle}>
            Cargando prospectos...
          </h3>

          <p style={emptyText}>
            Estamos obteniendo los prospectos
            registrados en Recursos Humanos.
          </p>

        </div>

      )}

      {/* ==================================================
          ERROR
      ================================================== */}

      {!loading && error && (

        <div style={errorBox}>

          <div style={errorTitle}>
            ❌ No se pudieron cargar los prospectos
          </div>

          <p style={errorMessage}>
            {error}
          </p>

          <button
            type="button"
            onClick={cargarProspectos}
            style={retryButton}
          >
            🔄 Reintentar
          </button>

        </div>

      )}

      {/* ==================================================
          SIN RESULTADOS
      ================================================== */}

      {!loading &&
        !error &&
        prospectosFiltrados.length === 0 && (

          <div style={empty}>

            <div style={emptyIcon}>
              👤
            </div>

            <h3 style={emptyTitle}>
              {busqueda
                ? "No se encontraron prospectos"
                : "Todavía no hay prospectos"}
            </h3>

            <p style={emptyText}>
              {busqueda
                ? "Prueba con otro nombre, correo, teléfono, puesto o ID."
                : "Los prospectos registrados aparecerán aquí."}
            </p>

          </div>
        )}

      {/* ==================================================
          TARJETAS
      ================================================== */}

      {!loading &&
        !error &&
        prospectosFiltrados.length > 0 && (

          <div style={grid}>

            {prospectosFiltrados.map(
              (prospecto) => {

                const estado =
                  obtenerEstado(prospecto);

                const idMirror =
                  obtenerIdMirror(prospecto);

                const id =
                  prospecto?.id_prospecto ||
                  prospecto?.id ||
                  prospecto?.correo ||
                  prospecto?.nombre;

                return (

                  <div
                    key={id}
                    style={prospectCard}
                  >

                    {/* ==================================
                        INFORMACIÓN PRINCIPAL
                    ================================== */}

                    <div style={cardHeader}>

                      <div style={avatar}>
                        {obtenerInicial(
                          prospecto
                        )}
                      </div>

                      <div style={personInfo}>

                        <h3 style={prospectName}>
                          {obtenerNombre(
                            prospecto
                          )}
                        </h3>

                        {idMirror && (

                          <div style={mirrorIdLabel}>

                            <span>
                              🆔
                            </span>

                            <span>
                              ID MirrorSoul
                            </span>

                          </div>

                        )}

                        {idMirror && (

                          <div style={mirrorId}>
                            {idMirror}
                          </div>

                        )}

                      </div>

                      {/* ESTADO */}

                      <span
                        style={{
                          ...statusBadge,
                          background:
                            estado.fondo,
                          color:
                            estado.color,
                        }}
                      >
                        {estado.texto}
                      </span>

                    </div>

                    {/* ==================================
                        DATOS
                    ================================== */}

                    <div style={detailsGrid}>

                      <div style={detailBox}>

                        <div style={detailLabel}>
                          SEXO
                        </div>

                        <div style={detailValue}>
                          {obtenerSexo(
                            prospecto
                          )}
                        </div>

                      </div>

                      <div style={detailBox}>

                        <div style={detailLabel}>
                          EDAD
                        </div>

                        <div style={detailValue}>
                          {obtenerEdad(
                            prospecto
                          )}
                        </div>

                      </div>

                    </div>

                    {/* ==================================
                        PUESTO
                    ================================== */}

                    <div style={extraInfo}>

                      <span style={extraIcon}>
                        💼
                      </span>

                      <div>

                        <div style={extraLabel}>
                          PUESTO AL QUE ASPIRA
                        </div>

                        <div style={extraValue}>
                          {prospecto?.puesto ||
                            prospecto?.puesto_aspira ||
                            "No registrado"}
                        </div>

                      </div>

                    </div>

                    {/* ==================================
                        ACCIONES
                    ================================== */}

                    <div style={actions}>

                      <button
                        type="button"
                        onClick={() =>
                          abrirDetalle(
                            prospecto
                          )
                        }
                        style={primaryButton}
                      >

                        <span>
                          📄
                        </span>

                        <span>
                          Ver expediente
                        </span>

                        <span style={arrow}>
                          →
                        </span>

                      </button>

                      <button
                        type="button"
                        onClick={() =>
                          abrirSeguimiento(
                            prospecto
                          )
                        }
                        style={secondaryButton}
                      >

                        <span>
                          📋
                        </span>

                        <span>
                          Seguimiento
                        </span>

                      </button>

                    </div>

                  </div>
                );
              }
            )}

          </div>
        )}

      {/* ==================================================
          VOLVER AL INICIO
      ================================================== */}

      <button
        type="button"
        onClick={onBack}
        style={homeButton}
      >
        ⬅️ Volver al inicio
      </button>

      {/* ==================================================
          FOOTER
      ================================================== */}

      <div style={footer}>

        <span>
          🧠 MirrorSoul
        </span>

        <span>
          Recursos Humanos · Prospectos
        </span>

      </div>

    </div>
  );
};

// ==================================================
// ESTILOS
// ==================================================

const container = {
  maxWidth: "1200px",
  margin: "0 auto",
  padding: "78px 0 30px",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
  color: "#172B4D",
};

const header = {
  display: "flex",
  alignItems: "flex-start",
  justifyContent: "space-between",
  gap: "30px",
  marginBottom: "28px",
};

const headerLeft = {
  flex: 1,
};

const brand = {
  fontSize: "13px",
  fontWeight: "800",
  letterSpacing: "4px",
  color: "#6574CD",
  marginBottom: "8px",
};

const title = {
  margin: 0,
  fontSize: "36px",
  fontWeight: "800",
  color: "#17345F",
  display: "flex",
  alignItems: "center",
  gap: "12px",
};

const titleIcon = {
  fontSize: "31px",
};

const subtitle = {
  margin: "8px 0 0",
  color: "#6880A3",
  fontSize: "16px",
  lineHeight: 1.5,
};

const countBox = {
  width: "140px",
  minWidth: "140px",
  height: "92px",
  borderRadius: "22px",
  background: "#FFFFFF",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
  boxShadow:
    "0 12px 30px rgba(40,80,140,0.09)",
};

const countNumber = {
  fontSize: "29px",
  fontWeight: "800",
  color: "#173E70",
  lineHeight: 1,
};

const countLabel = {
  marginTop: "8px",
  fontSize: "13px",
  color: "#7186A5",
};

const searchBox = {
  display: "flex",
  alignItems: "center",
  gap: "14px",
  background: "#FFFFFF",
  borderRadius: "18px",
  padding: "0 22px",
  height: "64px",
  boxShadow:
    "0 10px 28px rgba(40,80,140,0.09)",
  border: "1px solid #E1E8F0",
};

const searchIcon = {
  fontSize: "23px",
};

const searchInput = {
  flex: 1,
  border: "none",
  outline: "none",
  background: "transparent",
  fontSize: "16px",
  color: "#334E68",
};

const counter = {
  margin: "18px 5px 20px",
  color: "#6880A3",
  fontSize: "14px",
};

const grid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap: "24px",
};

const prospectCard = {
  background: "#FFFFFF",
  borderRadius: "22px",
  padding: "26px",
  boxShadow:
    "0 12px 30px rgba(40,80,140,0.09)",
  border: "1px solid #E5EAF1",
};

const cardHeader = {
  display: "flex",
  alignItems: "flex-start",
  gap: "16px",
  minHeight: "74px",
};

const avatar = {
  width: "66px",
  height: "66px",
  minWidth: "66px",
  borderRadius: "20px",
  background:
    "linear-gradient(135deg, #5A6ED0, #3B9DE8)",
  color: "#FFFFFF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "27px",
  fontWeight: "800",
};

const personInfo = {
  flex: 1,
  minWidth: 0,
};

const prospectName = {
  margin: "0 0 7px",
  fontSize: "21px",
  fontWeight: "800",
  color: "#17345F",
  textTransform: "none",
};

const mirrorIdLabel = {
  display: "flex",
  alignItems: "center",
  gap: "5px",
  color: "#7186A5",
  fontSize: "12px",
};

const mirrorId = {
  marginTop: "2px",
  color: "#5D6F9E",
  fontSize: "12px",
  fontWeight: "700",
};

const statusBadge = {
  padding: "8px 13px",
  borderRadius: "20px",
  fontSize: "12px",
  fontWeight: "800",
  whiteSpace: "nowrap",
};

const detailsGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap: "10px",
  marginTop: "20px",
};

const detailBox = {
  background: "#F7FAFC",
  borderRadius: "13px",
  padding: "13px 15px",
};

const detailLabel = {
  color: "#8A9BB2",
  fontSize: "11px",
  fontWeight: "800",
  marginBottom: "6px",
};

const detailValue = {
  color: "#1A2B4B",
  fontSize: "15px",
  fontWeight: "700",
};

const extraInfo = {
  display: "flex",
  alignItems: "center",
  gap: "10px",
  marginTop: "12px",
  padding: "12px 14px",
  background: "#F8FAFD",
  borderRadius: "12px",
};

const extraIcon = {
  fontSize: "18px",
};

const extraLabel = {
  color: "#8A9BB2",
  fontSize: "10px",
  fontWeight: "800",
  marginBottom: "3px",
};

const extraValue = {
  color: "#526987",
  fontSize: "13px",
  fontWeight: "600",
};

const actions = {
  display: "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap: "10px",
  marginTop: "18px",
};

const primaryButton = {
  border: "none",
  background: "#2867D7",
  color: "#FFFFFF",
  minHeight: "47px",
  borderRadius: "12px",
  cursor: "pointer",
  fontWeight: "800",
  fontSize: "14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: "7px",
  boxShadow:
    "0 6px 14px rgba(40,103,215,0.20)",
};

const secondaryButton = {
  border: "none",
  background: "#5967C5",
  color: "#FFFFFF",
  minHeight: "47px",
  borderRadius: "12px",
  cursor: "pointer",
  fontWeight: "800",
  fontSize: "14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: "7px",
};

const arrow = {
  marginLeft: "auto",
  marginRight: "8px",
  fontSize: "18px",
};

const homeButton = {
  border: "none",
  background: "#E5F2FC",
  color: "#2870C8",
  padding: "13px 20px",
  borderRadius: "13px",
  cursor: "pointer",
  fontWeight: "800",
  fontSize: "14px",
  marginTop: "36px",
};

const footer = {
  display: "flex",
  justifyContent: "space-between",
  gap: "15px",
  flexWrap: "wrap",
  borderTop: "1px solid #E1E7EF",
  marginTop: "78px",
  paddingTop: "22px",
  color: "#8CA0BA",
  fontSize: "13px",
};

const empty = {
  padding: "65px 30px",
  textAlign: "center",
  background: "#FFFFFF",
  borderRadius: "20px",
  boxShadow:
    "0 10px 28px rgba(40,80,140,0.07)",
};

const loadingIcon = {
  fontSize: "42px",
  marginBottom: "10px",
};

const emptyIcon = {
  fontSize: "46px",
  marginBottom: "10px",
};

const emptyTitle = {
  margin: "0 0 8px",
  color: "#334E68",
};

const emptyText = {
  margin: "0 auto",
  maxWidth: "520px",
  color: "#718096",
  lineHeight: 1.5,
};

const errorBox = {
  padding: "24px",
  background: "#FFF1F1",
  color: "#C62828",
  border: "1px solid #FFD5D5",
  borderRadius: "15px",
};

const errorTitle = {
  fontWeight: "800",
  fontSize: "16px",
};

const errorMessage = {
  margin: "8px 0 15px",
};

const retryButton = {
  border: "none",
  background: "#C62828",
  color: "#FFFFFF",
  padding: "10px 16px",
  borderRadius: "9px",
  cursor: "pointer",
  fontWeight: "700",
};

// ==================================================
// EXPORT
// ==================================================

export default ProspectosRH;