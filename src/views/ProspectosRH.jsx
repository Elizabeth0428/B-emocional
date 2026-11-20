// ==================================================
// src/views/ProspectosRH.jsx
// ==================================================

import React, {
  useEffect,
  useState
} from "react";

import {
  useNavigate
} from "react-router-dom";

import {
  getToken,
  clearSession
} from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;


// ==================================================
// COMPONENTE
// ==================================================

const ProspectosRH = () => {

  const navigate =
    useNavigate();


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    prospectos,
    setProspectos
  ] =
    useState([]);

  const [
    loading,
    setLoading
  ] =
    useState(true);

  const [
    error,
    setError
  ] =
    useState("");

  const [
    busqueda,
    setBusqueda
  ] =
    useState("");

  const [
    vista,
    setVista
  ] =
    useState("activos");

  const [
    filtroHistorial,
    setFiltroHistorial
  ] =
    useState("todos");

  const [
    resumenAbierto,
    setResumenAbierto
  ] =
    useState(null);


  // ==================================================
  // CARGAR PROSPECTOS
  // ==================================================

  const cargarProspectos =
    async () => {

      try {

        setLoading(true);
        setError("");


        const token =
          getToken();


        if (!token) {

          clearSession();

          navigate(
            "/login",
            {
              replace: true
            }
          );

          return;
        }


        const response =
          await fetch(
            `${API_URL}/api/prospectos`,
            {
              method:
                "GET",

              headers: {
                Authorization:
                  `Bearer ${token}`,

                "Content-Type":
                  "application/json"
              }
            }
          );


        const data =
          await response
            .json()
            .catch(
              () => ({})
            );


        if (
          response.status === 401
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


        if (
          response.status === 403
        ) {

          throw new Error(
            data?.message ||
            "No tienes permiso para consultar prospectos."
          );

        }


        if (
          !response.ok
        ) {

          throw new Error(
            data?.message ||
            `Error HTTP ${response.status}`
          );

        }


        let lista = [];


        if (
          Array.isArray(
            data
          )
        ) {

          lista =
            data;

        } else if (
          Array.isArray(
            data?.prospectos
          )
        ) {

          lista =
            data.prospectos;

        } else if (
          Array.isArray(
            data?.data
          )
        ) {

          lista =
            data.data;

        }


        console.log(
          "📦 Prospectos recibidos:",
          lista
        );


        setProspectos(
          lista
        );


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

  useEffect(
    () => {

      cargarProspectos();

    },
    []
  );


  // ==================================================
  // ESTADO NORMALIZADO
  // ==================================================

  const obtenerEstadoTexto =
    prospecto => {

      return String(
        prospecto?.estatus ||
        prospecto?.estado ||
        "prospecto"
      )
        .trim()
        .toLowerCase();

    };


  // ==================================================
  // ACTIVOS / HISTORIAL
  // ==================================================

  const prospectosActivos =
    prospectos.filter(
      prospecto => {

        const estado =
          obtenerEstadoTexto(
            prospecto
          );

        return (
          estado !==
            "contratado" &&
          estado !==
            "no_contratado"
        );

      }
    );


  const prospectosHistorial =
    prospectos.filter(
      prospecto => {

        const estado =
          obtenerEstadoTexto(
            prospecto
          );

        return (
          estado ===
            "contratado" ||
          estado ===
            "no_contratado"
        );

      }
    );


  const totalContratados =
    prospectosHistorial.filter(
      prospecto =>
        obtenerEstadoTexto(
          prospecto
        ) ===
        "contratado"
    ).length;


  const totalNoContratados =
    prospectosHistorial.filter(
      prospecto =>
        obtenerEstadoTexto(
          prospecto
        ) ===
        "no_contratado"
    ).length;


  // ==================================================
  // LISTA ACTUAL
  // ==================================================

  let listaActual =
    vista === "historial"
      ? prospectosHistorial
      : prospectosActivos;


  if (
    vista === "historial" &&
    filtroHistorial !== "todos"
  ) {

    listaActual =
      listaActual.filter(
        prospecto =>
          obtenerEstadoTexto(
            prospecto
          ) ===
          filtroHistorial
      );

  }


  // ==================================================
  // BUSCADOR
  // ==================================================

  const prospectosFiltrados =
    listaActual.filter(
      prospecto => {

        const texto =
          busqueda
            .toLowerCase()
            .trim();


        if (!texto) {
          return true;
        }


        return (

          String(
            prospecto?.nombre ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            ) ||

          String(
            prospecto?.correo ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            ) ||

          String(
            prospecto?.puesto ||
            prospecto?.puesto_aspira ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            ) ||

          String(
            prospecto?.telefono ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            ) ||

          String(
            prospecto?.id_mirror ||
            prospecto?.mirror_id ||
            prospecto?.codigo ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            ) ||

          String(
            prospecto?.motivo ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            ) ||

          String(
            prospecto?.observacion_final ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            ) ||

          obtenerEstadoTexto(
            prospecto
          )
            .includes(
              texto
            )

        );

      }
    );


  // ==================================================
  // ESTADO VISUAL
  // ==================================================

  const obtenerEstado =
    prospecto => {

      const estado =
        obtenerEstadoTexto(
          prospecto
        );


      const estados = {

        prospecto: {
          texto:
            "Prospecto",
          fondo:
            "#FFF7E6",
          color:
            "#B7791F"
        },

        en_proceso: {
          texto:
            "En proceso",
          fondo:
            "#EEF4FF",
          color:
            "#2167D5"
        },

        evaluacion: {
          texto:
            "En evaluación",
          fondo:
            "#F3E9FF",
          color:
            "#7540D5"
        },

        aprobado: {
          texto:
            "Aprobado",
          fondo:
            "#ECF9EF",
          color:
            "#3BAE55"
        },

        contratado: {
          texto:
            "Contratado",
          fondo:
            "#E8F8ED",
          color:
            "#27843A"
        },

        no_contratado: {
          texto:
            "No contratado",
          fondo:
            "#FFF1F1",
          color:
            "#C62828"
        }

      };


      return (
        estados[
          estado
        ] ||
        estados.prospecto
      );

    };


  // ==================================================
  // DATOS
  // ==================================================

  const obtenerIdProspecto =
    prospecto => {

      return (
        prospecto?.id_prospecto ||
        prospecto?.id ||
        null
      );

    };


  const obtenerIdMirror =
    prospecto => {

      return (
        prospecto?.id_mirror ||
        prospecto?.mirror_id ||
        prospecto?.codigo ||
        null
      );

    };


  const obtenerNombre =
    prospecto => {

      return (
        prospecto?.nombre ||
        "Prospecto sin nombre"
      );

    };


  const obtenerInicial =
    prospecto => {

      return obtenerNombre(
        prospecto
      )
        .trim()
        .charAt(0)
        .toUpperCase();

    };


  const obtenerSexo =
    prospecto => {

      const sexo =
        String(
          prospecto?.sexo ||
          prospecto?.genero ||
          ""
        )
          .trim()
          .toUpperCase();


      if (
        sexo === "M"
      ) {
        return "Masculino";
      }


      if (
        sexo === "F"
      ) {
        return "Femenino";
      }


      return "No especificado";

    };


  const obtenerEdad =
    prospecto => {

      if (
        prospecto?.edad !==
          undefined &&
        prospecto?.edad !==
          null &&
        prospecto?.edad !==
          ""
      ) {

        return `${prospecto.edad} años`;

      }


      return "No especificada";

    };


  const formatearFecha =
    fecha => {

      if (!fecha) {
        return "Sin fecha";
      }


      try {

        return new Date(
          fecha
        ).toLocaleDateString(
          "es-MX",
          {
            day:
              "2-digit",
            month:
              "short",
            year:
              "numeric"
          }
        );

      } catch {

        return "Sin fecha";

      }

    };


  const obtenerMotivo =
    prospecto => {

      return (
        prospecto?.motivo ||
        (
          obtenerEstadoTexto(
            prospecto
          ) === "contratado"
            ? "Proceso finalizado con contratación"
            : "Sin motivo registrado"
        )
      );

    };


  const obtenerObservacion =
    prospecto => {

      return (
        prospecto?.observacion_final ||
        "Sin observación final"
      );

    };


  const obtenerResumenPruebas =
    prospecto => {

      const valor =
        prospecto?.resumen_pruebas;


      if (!valor) {
        return [];
      }


      if (
        Array.isArray(
          valor
        )
      ) {
        return valor;
      }


      try {

        const parsed =
          JSON.parse(
            valor
          );


        return Array.isArray(
          parsed
        )
          ? parsed
          : [];


      } catch {

        return [];

      }

    };


  // ==================================================
  // NAVEGACIÓN
  // ==================================================

  const abrirDetalle =
    prospecto => {

      const id =
        obtenerIdProspecto(
          prospecto
        );


      if (!id) {

        alert(
          "No se pudo identificar el prospecto."
        );

        return;
      }


      navigate(
        `/prospecto/${id}`
      );

    };


  const abrirSeguimiento =
    prospecto => {

      const id =
        obtenerIdProspecto(
          prospecto
        );


      if (!id) {

        alert(
          "No se pudo identificar el prospecto."
        );

        return;
      }


      navigate(
        `/prospecto/${id}/seguimiento`
      );

    };


  const volverInicio =
    () => {

      navigate(
        "/dashboard",
        {
          replace: true
        }
      );

    };


  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div style={container}>

      {/* =================================================
          HEADER
      ================================================= */}

      <div style={header}>

        <div style={headerLeft}>

          <div style={brand}>
            MIRRORSOUL
          </div>


          <h1 style={title}>

            <span style={titleIcon}>
              👥
            </span>

            Prospectos

          </h1>


          <p style={subtitle}>
            Consulta procesos activos y el historial de selección de Recursos Humanos.
          </p>

        </div>


        <div style={countBox}>

          <div style={countNumber}>

            {
              vista === "historial"
                ? prospectosHistorial.length
                : prospectosActivos.length
            }

          </div>


          <div style={countLabel}>

            {
              vista === "historial"
                ? "procesos cerrados"
                : "prospectos activos"
            }

          </div>

        </div>

      </div>


      {/* =================================================
          PESTAÑAS
      ================================================= */}

      <div style={tabsBox}>

        <button
          type="button"
          onClick={() => {

            setVista(
              "activos"
            );

            setBusqueda("");

            setResumenAbierto(
              null
            );

          }}
          style={{
            ...tabButton,

            ...(vista === "activos"
              ? tabButtonActive
              : {})
          }}
        >
          👥 Procesos activos

          <span style={tabCounter}>
            {prospectosActivos.length}
          </span>
        </button>


        <button
          type="button"
          onClick={() => {

            setVista(
              "historial"
            );

            setBusqueda("");

            setResumenAbierto(
              null
            );

          }}
          style={{
            ...tabButton,

            ...(vista === "historial"
              ? tabButtonActive
              : {})
          }}
        >
          📚 Historial de selección

          <span style={tabCounter}>
            {prospectosHistorial.length}
          </span>
        </button>

      </div>


      {/* =================================================
          FILTROS HISTORIAL
      ================================================= */}

      {
        vista === "historial" && (

          <div style={historyFilters}>

            <button
              type="button"
              onClick={() =>
                setFiltroHistorial(
                  "todos"
                )
              }
              style={{
                ...historyFilterButton,

                ...(filtroHistorial ===
                "todos"
                  ? historyFilterActive
                  : {})
              }}
            >
              Todos ({prospectosHistorial.length})
            </button>


            <button
              type="button"
              onClick={() =>
                setFiltroHistorial(
                  "contratado"
                )
              }
              style={{
                ...historyFilterButton,

                ...(filtroHistorial ===
                "contratado"
                  ? historyFilterActive
                  : {})
              }}
            >
              ✅ Contratados ({totalContratados})
            </button>


            <button
              type="button"
              onClick={() =>
                setFiltroHistorial(
                  "no_contratado"
                )
              }
              style={{
                ...historyFilterButton,

                ...(filtroHistorial ===
                "no_contratado"
                  ? historyFilterActive
                  : {})
              }}
            >
              ❌ No contratados ({totalNoContratados})
            </button>

          </div>

        )
      }


      {/* =================================================
          BUSCADOR
      ================================================= */}

      <div style={searchBox}>

        <span style={searchIcon}>
          🔎
        </span>


        <input
          type="text"
          value={busqueda}
          onChange={
            e =>
              setBusqueda(
                e.target.value
              )
          }
          placeholder={
            vista === "historial"
              ? "Buscar por nombre, puesto, motivo o ID..."
              : "Buscar por nombre, correo, puesto o ID..."
          }
          style={searchInput}
        />

      </div>


      {/* =================================================
          CONTADOR
      ================================================= */}

      {
        !loading &&
        !error && (

          <div style={counter}>

            Mostrando{" "}

            <strong>
              {prospectosFiltrados.length}
            </strong>

            {
              vista === "historial"
                ? prospectosFiltrados.length === 1
                  ? " proceso cerrado"
                  : " procesos cerrados"

                : prospectosFiltrados.length === 1
                  ? " prospecto"
                  : " prospectos"
            }

          </div>

        )
      }


      {/* =================================================
          CARGANDO
      ================================================= */}

      {
        loading && (

          <div style={empty}>

            <div style={loadingIcon}>
              ⏳
            </div>

            <h3 style={emptyTitle}>
              Cargando prospectos...
            </h3>

          </div>

        )
      }


      {/* =================================================
          ERROR
      ================================================= */}

      {
        !loading &&
        error && (

          <div style={errorBox}>

            <div style={errorTitle}>
              ❌ No se pudieron cargar los prospectos
            </div>


            <p style={errorMessage}>
              {error}
            </p>


            <button
              type="button"
              onClick={
                cargarProspectos
              }
              style={retryButton}
            >
              🔄 Reintentar
            </button>

          </div>

        )
      }


      {/* =================================================
          SIN RESULTADOS
      ================================================= */}

      {
        !loading &&
        !error &&
        prospectosFiltrados.length === 0 && (

          <div style={empty}>

            <div style={emptyIcon}>

              {
                vista === "historial"
                  ? "📚"
                  : "👤"
              }

            </div>


            <h3 style={emptyTitle}>

              {
                busqueda
                  ? "No se encontraron resultados"

                  : vista === "historial"
                    ? "Todavía no hay procesos cerrados"

                    : "Todavía no hay prospectos activos"
              }

            </h3>


            <p style={emptyText}>

              {
                vista === "historial"
                  ? "Aquí aparecerán las personas que terminen su proceso de selección."
                  : "Los nuevos candidatos en proceso de selección aparecerán aquí."
              }

            </p>

          </div>

        )
      }


      {/* =================================================
          HISTORIAL COMPACTO
      ================================================= */}

      {
        !loading &&
        !error &&
        prospectosFiltrados.length > 0 &&
        vista === "historial" && (

          <div style={historyList}>

            {prospectosFiltrados.map(
              prospecto => {

                const estado =
                  obtenerEstado(
                    prospecto
                  );


                const id =
                  obtenerIdProspecto(
                    prospecto
                  ) ||
                  prospecto?.correo ||
                  prospecto?.nombre;


                const idMirror =
                  obtenerIdMirror(
                    prospecto
                  );


                const motivo =
                  obtenerMotivo(
                    prospecto
                  );


                const fecha =
                  prospecto?.fecha_decision ||
                  prospecto?.fecha_actualizacion ||
                  null;


                const abierto =
                  resumenAbierto === id;


                const pruebas =
                  obtenerResumenPruebas(
                    prospecto
                  );


                return (

                  <React.Fragment
                    key={id}
                  >

                    <div style={historyRow}>

                      {/* PERSONA */}

                      <div style={historyNameBox}>

                        <div style={historyAvatar}>
                          {obtenerInicial(
                            prospecto
                          )}
                        </div>


                        <div style={historyNameInfo}>

                          <div style={historyName}>
                            {obtenerNombre(
                              prospecto
                            )}
                          </div>


                          <div style={historyMirror}>
                            🆔 {idMirror || "Sin ID"}
                          </div>

                        </div>

                      </div>


                      {/* PUESTO */}

                      <div style={historyCell}>

                        <span style={historyLabel}>
                          Puesto
                        </span>

                        <strong style={historyValue}>
                          {
                            prospecto?.puesto ||
                            prospecto?.puesto_aspira ||
                            "No registrado"
                          }
                        </strong>

                      </div>


                      {/* RESULTADO */}

                      <div style={historyCell}>

                        <span style={historyLabel}>
                          Resultado
                        </span>

                        <span
                          style={{
                            ...historyStatus,
                            background:
                              estado.fondo,
                            color:
                              estado.color
                          }}
                        >
                          {estado.texto}
                        </span>

                      </div>


                      {/* MOTIVO */}

                      <div style={historyCellWide}>

                        <span style={historyLabel}>
                          Motivo
                        </span>

                        <span
                          style={historyValueEllipsis}
                          title={motivo}
                        >
                          {motivo}
                        </span>

                      </div>


                      {/* FECHA */}

                      <div style={historyCell}>

                        <span style={historyLabel}>
                          Fecha
                        </span>

                        <span style={historyValue}>
                          {formatearFecha(
                            fecha
                          )}
                        </span>

                      </div>


                      {/* VER RESUMEN */}

                      <button
                        type="button"
                        onClick={() =>
                          setResumenAbierto(
                            abierto
                              ? null
                              : id
                          )
                        }
                        style={historyButton}
                      >
                        {
                          abierto
                            ? "Cerrar"
                            : "Ver resumen"
                        }

                        <span>
                          {
                            abierto
                              ? "↑"
                              : "↓"
                          }
                        </span>
                      </button>

                    </div>


                    {/* =================================================
                        RESUMEN DESPLEGABLE
                    ================================================= */}

                    {
                      abierto && (

                        <div style={summaryPanel}>

                          <div style={summaryItem}>

                            <span style={summaryLabel}>
                              Motivo
                            </span>

                            <strong>
                              {obtenerMotivo(
                                prospecto
                              )}
                            </strong>

                          </div>


                          <div style={summaryItem}>

                            <span style={summaryLabel}>
                              Observación final
                            </span>

                            <span>
                              {obtenerObservacion(
                                prospecto
                              )}
                            </span>

                          </div>


                          <div style={summaryItemWide}>

                            <span style={summaryLabel}>
                              Evaluaciones relevantes
                            </span>


                            {
                              pruebas.length > 0 ? (

                                <div style={testsRow}>

                                  {pruebas.map(
                                    (
                                      prueba,
                                      index
                                    ) => (

                                      <span
                                        key={
                                          `${id}-${index}`
                                        }
                                        style={testChip}
                                      >
                                        🧪 {
                                          prueba?.prueba ||
                                          "Prueba"
                                        }

                                        {
                                          prueba?.resultado_texto
                                            ? `: ${prueba.resultado_texto}`
                                            : prueba?.puntaje_total
                                              ? `: ${prueba.puntaje_total}`
                                              : ""
                                        }
                                      </span>

                                    )
                                  )}

                                </div>

                              ) : (

                                <span style={emptySummary}>
                                  Sin evaluaciones resumidas.
                                </span>

                              )
                            }

                          </div>

                        </div>

                      )
                    }

                  </React.Fragment>

                );

              }
            )}

          </div>

        )
      }


      {/* =================================================
          PROSPECTOS ACTIVOS
      ================================================= */}

      {
        !loading &&
        !error &&
        prospectosFiltrados.length > 0 &&
        vista === "activos" && (

          <div style={grid}>

            {prospectosFiltrados.map(
              prospecto => {

                const estado =
                  obtenerEstado(
                    prospecto
                  );


                const idMirror =
                  obtenerIdMirror(
                    prospecto
                  );


                const id =
                  obtenerIdProspecto(
                    prospecto
                  ) ||
                  prospecto?.correo ||
                  prospecto?.nombre;


                return (

                  <div
                    key={id}
                    style={prospectCard}
                  >

                    {/* CABECERA */}

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


                        {
                          idMirror && (
                            <>

                              <div style={mirrorIdLabel}>
                                🆔 ID MirrorSoul
                              </div>


                              <div style={mirrorId}>
                                {idMirror}
                              </div>

                            </>
                          )
                        }

                      </div>


                      <span
                        style={{
                          ...statusBadge,
                          background:
                            estado.fondo,
                          color:
                            estado.color
                        }}
                      >
                        {estado.texto}
                      </span>

                    </div>


                    {/* DATOS */}

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


                    {/* PUESTO */}

                    <div style={extraInfo}>

                      <span style={extraIcon}>
                        💼
                      </span>


                      <div>

                        <div style={extraLabel}>
                          PUESTO AL QUE ASPIRA
                        </div>


                        <div style={extraValue}>
                          {
                            prospecto?.puesto ||
                            prospecto?.puesto_aspira ||
                            "No registrado"
                          }
                        </div>

                      </div>

                    </div>


                    {/* ACCIONES */}

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
                        📄 Ver expediente

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
                        📋 Seguimiento
                      </button>

                    </div>

                  </div>

                );

              }
            )}

          </div>

        )
      }


      {/* =================================================
          VOLVER
      ================================================= */}

      <button
        type="button"
        onClick={
          volverInicio
        }
        style={homeButton}
      >
        ⬅️ Volver al inicio
      </button>


      {/* =================================================
          FOOTER
      ================================================= */}

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
  maxWidth:
    "1400px",
  margin:
    "0 auto",
  padding:
    "78px 24px 30px",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
  color:
    "#172B4D"
};


const header = {
  display:
    "flex",
  alignItems:
    "flex-start",
  justifyContent:
    "space-between",
  gap:
    "30px",
  marginBottom:
    "28px"
};


const headerLeft = {
  flex:
    1
};


const brand = {
  fontSize:
    "13px",
  fontWeight:
    "800",
  letterSpacing:
    "4px",
  color:
    "#6574CD",
  marginBottom:
    "8px"
};


const title = {
  margin:
    0,
  fontSize:
    "36px",
  fontWeight:
    "800",
  color:
    "#17345F",
  display:
    "flex",
  alignItems:
    "center",
  gap:
    "12px"
};


const titleIcon = {
  fontSize:
    "31px"
};


const subtitle = {
  margin:
    "8px 0 0",
  color:
    "#6880A3",
  fontSize:
    "16px",
  lineHeight:
    1.5
};


const countBox = {
  width:
    "140px",
  minWidth:
    "140px",
  height:
    "92px",
  borderRadius:
    "22px",
  background:
    "#FFFFFF",
  display:
    "flex",
  flexDirection:
    "column",
  alignItems:
    "center",
  justifyContent:
    "center",
  boxShadow:
    "0 12px 30px rgba(40,80,140,0.09)"
};


const countNumber = {
  fontSize:
    "29px",
  fontWeight:
    "800",
  color:
    "#173E70",
  lineHeight:
    1
};


const countLabel = {
  marginTop:
    "8px",
  fontSize:
    "13px",
  color:
    "#7186A5",
  textAlign:
    "center"
};


// ==================================================
// PESTAÑAS
// ==================================================

const tabsBox = {
  display:
    "flex",
  gap:
    "12px",
  marginBottom:
    "16px",
  flexWrap:
    "wrap"
};


const tabButton = {
  border:
    "1px solid #DCE5F0",
  background:
    "#FFFFFF",
  color:
    "#5D718E",
  padding:
    "13px 18px",
  borderRadius:
    "14px",
  cursor:
    "pointer",
  fontWeight:
    "800",
  fontSize:
    "14px",
  display:
    "flex",
  alignItems:
    "center",
  gap:
    "9px"
};


const tabButtonActive = {
  background:
    "#EEF4FF",
  color:
    "#2167D5",
  border:
    "1px solid #BFD3F6"
};


const tabCounter = {
  background:
    "#FFFFFF",
  border:
    "1px solid #D8E1ED",
  borderRadius:
    "20px",
  padding:
    "2px 8px",
  fontSize:
    "11px"
};


// ==================================================
// FILTROS
// ==================================================

const historyFilters = {
  display:
    "flex",
  gap:
    "8px",
  marginBottom:
    "18px",
  flexWrap:
    "wrap"
};


const historyFilterButton = {
  border:
    "1px solid #DFE6EE",
  background:
    "#FFFFFF",
  color:
    "#64748B",
  borderRadius:
    "20px",
  padding:
    "8px 13px",
  fontSize:
    "12px",
  fontWeight:
    "700",
  cursor:
    "pointer"
};


const historyFilterActive = {
  background:
    "#173E70",
  color:
    "#FFFFFF",
  border:
    "1px solid #173E70"
};


// ==================================================
// BUSCADOR
// ==================================================

const searchBox = {
  display:
    "flex",
  alignItems:
    "center",
  gap:
    "14px",
  background:
    "#FFFFFF",
  borderRadius:
    "18px",
  padding:
    "0 22px",
  height:
    "64px",
  boxShadow:
    "0 10px 28px rgba(40,80,140,0.09)",
  border:
    "1px solid #E1E8F0"
};


const searchIcon = {
  fontSize:
    "23px"
};


const searchInput = {
  flex:
    1,
  border:
    "none",
  outline:
    "none",
  background:
    "transparent",
  fontSize:
    "16px",
  color:
    "#334E68"
};


const counter = {
  margin:
    "18px 5px 20px",
  color:
    "#6880A3",
  fontSize:
    "14px"
};


// ==================================================
// HISTORIAL COMPACTO
// ==================================================

const historyList = {
  display:
    "flex",
  flexDirection:
    "column",
  gap:
    "8px"
};


const historyRow = {
  display:
    "grid",

  gridTemplateColumns:
    "minmax(230px, 1.65fr) minmax(110px, .75fr) minmax(125px, .85fr) minmax(170px, 1.2fr) minmax(110px, .7fr) auto",

  alignItems:
    "center",

  gap:
    "14px",

  background:
    "#FFFFFF",

  border:
    "1px solid #E2E8F0",

  borderRadius:
    "12px",

  padding:
    "10px 13px",

  boxShadow:
    "0 4px 12px rgba(40,80,140,0.05)"
};


const historyNameBox = {
  display:
    "flex",
  alignItems:
    "center",
  gap:
    "10px",
  minWidth:
    0
};


const historyAvatar = {
  width:
    "38px",
  height:
    "38px",
  minWidth:
    "38px",
  borderRadius:
    "10px",
  background:
    "linear-gradient(135deg, #5A6ED0, #3B9DE8)",
  color:
    "#FFFFFF",
  display:
    "flex",
  alignItems:
    "center",
  justifyContent:
    "center",
  fontSize:
    "16px",
  fontWeight:
    "800"
};


const historyNameInfo = {
  minWidth:
    0
};


const historyName = {
  fontWeight:
    "800",
  fontSize:
    "14px",
  color:
    "#17345F",
  whiteSpace:
    "nowrap",
  overflow:
    "hidden",
  textOverflow:
    "ellipsis"
};


const historyMirror = {
  marginTop:
    "2px",
  color:
    "#7186A5",
  fontSize:
    "10px",
  whiteSpace:
    "nowrap"
};


const historyCell = {
  display:
    "flex",
  flexDirection:
    "column",
  gap:
    "4px",
  minWidth:
    0
};


const historyCellWide = {
  display:
    "flex",
  flexDirection:
    "column",
  gap:
    "4px",
  minWidth:
    0
};


const historyLabel = {
  color:
    "#8A9BB2",
  fontSize:
    "9px",
  fontWeight:
    "800",
  textTransform:
    "uppercase"
};


const historyValue = {
  color:
    "#334E68",
  fontSize:
    "12px",
  fontWeight:
    "600"
};


const historyValueEllipsis = {
  ...historyValue,
  whiteSpace:
    "nowrap",
  overflow:
    "hidden",
  textOverflow:
    "ellipsis"
};


const historyStatus = {
  padding:
    "5px 9px",
  borderRadius:
    "15px",
  fontSize:
    "10px",
  fontWeight:
    "800",
  whiteSpace:
    "nowrap",
  width:
    "fit-content"
};


const historyButton = {
  border:
    "none",
  background:
    "#2867D7",
  color:
    "#FFFFFF",
  padding:
    "9px 12px",
  borderRadius:
    "9px",
  cursor:
    "pointer",
  fontWeight:
    "800",
  fontSize:
    "11px",
  whiteSpace:
    "nowrap",
  display:
    "flex",
  alignItems:
    "center",
  justifyContent:
    "center",
  gap:
    "7px"
};


// ==================================================
// RESUMEN CERRADO
// ==================================================

const summaryPanel = {
  display:
    "grid",

  gridTemplateColumns:
    "minmax(180px,.8fr) minmax(220px,1fr) minmax(320px,2fr)",

  gap:
    "18px",

  margin:
    "-2px 8px 3px",

  padding:
    "11px 15px",

  background:
    "#F8FAFD",

  border:
    "1px solid #E1E8F0",

  borderTop:
    "none",

  borderRadius:
    "0 0 11px 11px",

  fontSize:
    "11px",

  color:
    "#526987"
};


const summaryItem = {
  display:
    "flex",
  flexDirection:
    "column",
  gap:
    "4px"
};


const summaryItemWide = {
  ...summaryItem
};


const summaryLabel = {
  color:
    "#8A9BB2",
  fontSize:
    "8px",
  fontWeight:
    "800",
  textTransform:
    "uppercase"
};


const testsRow = {
  display:
    "flex",
  flexWrap:
    "wrap",
  gap:
    "5px"
};


const testChip = {
  background:
    "#FFFFFF",
  border:
    "1px solid #DDE5EF",
  padding:
    "4px 7px",
  borderRadius:
    "7px",
  fontSize:
    "10px"
};


const emptySummary = {
  color:
    "#8A9BB2"
};


// ==================================================
// TARJETAS ACTIVOS
// ==================================================

const grid = {
  display:
    "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap:
    "24px"
};


const prospectCard = {
  background:
    "#FFFFFF",
  borderRadius:
    "22px",
  padding:
    "26px",
  boxShadow:
    "0 12px 30px rgba(40,80,140,0.09)",
  border:
    "1px solid #E5EAF1"
};


const cardHeader = {
  display:
    "flex",
  alignItems:
    "flex-start",
  gap:
    "16px",
  minHeight:
    "74px"
};


const avatar = {
  width:
    "66px",
  height:
    "66px",
  minWidth:
    "66px",
  borderRadius:
    "20px",
  background:
    "linear-gradient(135deg, #5A6ED0, #3B9DE8)",
  color:
    "#FFFFFF",
  display:
    "flex",
  alignItems:
    "center",
  justifyContent:
    "center",
  fontSize:
    "27px",
  fontWeight:
    "800"
};


const personInfo = {
  flex:
    1,
  minWidth:
    0
};


const prospectName = {
  margin:
    "0 0 7px",
  fontSize:
    "21px",
  fontWeight:
    "800",
  color:
    "#17345F"
};


const mirrorIdLabel = {
  display:
    "flex",
  alignItems:
    "center",
  gap:
    "5px",
  color:
    "#7186A5",
  fontSize:
    "12px"
};


const mirrorId = {
  marginTop:
    "2px",
  color:
    "#5D6F9E",
  fontSize:
    "12px",
  fontWeight:
    "700"
};


const statusBadge = {
  padding:
    "8px 13px",
  borderRadius:
    "20px",
  fontSize:
    "12px",
  fontWeight:
    "800",
  whiteSpace:
    "nowrap"
};


const detailsGrid = {
  display:
    "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap:
    "10px",
  marginTop:
    "20px"
};


const detailBox = {
  background:
    "#F7FAFC",
  borderRadius:
    "13px",
  padding:
    "13px 15px"
};


const detailLabel = {
  color:
    "#8A9BB2",
  fontSize:
    "11px",
  fontWeight:
    "800",
  marginBottom:
    "6px"
};


const detailValue = {
  color:
    "#1A2B4B",
  fontSize:
    "15px",
  fontWeight:
    "700"
};


const extraInfo = {
  display:
    "flex",
  alignItems:
    "center",
  gap:
    "10px",
  marginTop:
    "12px",
  padding:
    "12px 14px",
  background:
    "#F8FAFD",
  borderRadius:
    "12px"
};


const extraIcon = {
  fontSize:
    "18px"
};


const extraLabel = {
  color:
    "#8A9BB2",
  fontSize:
    "10px",
  fontWeight:
    "800",
  marginBottom:
    "3px"
};


const extraValue = {
  color:
    "#526987",
  fontSize:
    "13px",
  fontWeight:
    "600"
};


const actions = {
  display:
    "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap:
    "10px",
  marginTop:
    "18px"
};


const primaryButton = {
  border:
    "none",
  background:
    "#2867D7",
  color:
    "#FFFFFF",
  minHeight:
    "47px",
  borderRadius:
    "12px",
  cursor:
    "pointer",
  fontWeight:
    "800",
  fontSize:
    "14px",
  display:
    "flex",
  alignItems:
    "center",
  justifyContent:
    "center",
  gap:
    "7px",
  boxShadow:
    "0 6px 14px rgba(40,103,215,0.20)"
};


const secondaryButton = {
  border:
    "none",
  background:
    "#5967C5",
  color:
    "#FFFFFF",
  minHeight:
    "47px",
  borderRadius:
    "12px",
  cursor:
    "pointer",
  fontWeight:
    "800",
  fontSize:
    "14px",
  display:
    "flex",
  alignItems:
    "center",
  justifyContent:
    "center",
  gap:
    "7px"
};


const arrow = {
  marginLeft:
    "auto",
  marginRight:
    "8px",
  fontSize:
    "18px"
};


// ==================================================
// OTROS
// ==================================================

const homeButton = {
  border:
    "none",
  background:
    "#E5F2FC",
  color:
    "#2870C8",
  padding:
    "13px 20px",
  borderRadius:
    "13px",
  cursor:
    "pointer",
  fontWeight:
    "800",
  fontSize:
    "14px",
  marginTop:
    "36px"
};


const footer = {
  display:
    "flex",
  justifyContent:
    "space-between",
  gap:
    "15px",
  flexWrap:
    "wrap",
  borderTop:
    "1px solid #E1E7EF",
  marginTop:
    "78px",
  paddingTop:
    "22px",
  color:
    "#8CA0BA",
  fontSize:
    "13px"
};


const empty = {
  padding:
    "65px 30px",
  textAlign:
    "center",
  background:
    "#FFFFFF",
  borderRadius:
    "20px",
  boxShadow:
    "0 10px 28px rgba(40,80,140,0.07)"
};


const loadingIcon = {
  fontSize:
    "42px",
  marginBottom:
    "10px"
};


const emptyIcon = {
  fontSize:
    "46px",
  marginBottom:
    "10px"
};


const emptyTitle = {
  margin:
    "0 0 8px",
  color:
    "#334E68"
};


const emptyText = {
  margin:
    "0 auto",
  maxWidth:
    "520px",
  color:
    "#718096",
  lineHeight:
    1.5
};


const errorBox = {
  padding:
    "24px",
  background:
    "#FFF1F1",
  color:
    "#C62828",
  border:
    "1px solid #FFD5D5",
  borderRadius:
    "15px"
};


const errorTitle = {
  fontWeight:
    "800",
  fontSize:
    "16px"
};


const errorMessage = {
  margin:
    "8px 0 15px"
};


const retryButton = {
  border:
    "none",
  background:
    "#C62828",
  color:
    "#FFFFFF",
  padding:
    "10px 16px",
  borderRadius:
    "9px",
  cursor:
    "pointer",
  fontWeight:
    "700"
};


export default ProspectosRH;