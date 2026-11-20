import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useNavigate, useParams } from "react-router-dom";
import { getToken } from "../services/AuthService";
const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;
const Nom035Empleado = () => {
  const { idEmpleado } = useParams();
  const navigate = useNavigate();
  const token = getToken();
  const config = useMemo(
    () => ({
      headers: {
        Authorization: `Bearer ${token}`
      }
    }),
    [token]
  );
  const [empleado, setEmpleado] = useState(null);
  const [cuestionarios, setCuestionarios] = useState([]);
  const [aplicaciones, setAplicaciones] = useState([]);
  const [cargando, setCargando] = useState(true);
  const [habilitando, setHabilitando] = useState(false);
  const [procesandoId, setProcesandoId] = useState(null);
  const [error, setError] = useState("");
  const [mensaje, setMensaje] = useState("");
  const [infoNomAbierta, setInfoNomAbierta] = useState(false);
  const [aplicacionesAbiertas, setAplicacionesAbiertas] = useState({});
  const toggleAplicacion = idAplicacion => {
    setAplicacionesAbiertas(prev => ({
      ...prev,
      [idAplicacion]: !prev[idAplicacion]
    }));
  };
  const [form, setForm] = useState({
    id_cuestionario: "",
    tipo_aplicacion: "periodica",
    motivo: ""
  });
  // ==================================================
  // CARGAR DATOS
  // ==================================================
  const cargarDatos = useCallback(async () => {
    try {
      setCargando(true);
      setError("");
      if (!token) {
        throw new Error("Tu sesión no es válida.");
      }
      const [
        respuestaCuestionarios,
        respuestaAplicaciones
      ] = await Promise.all([
        axios.get(
          `${API_URL}/api/empleados/${idEmpleado}/nom035/cuestionarios`,
          config
        ),
        axios.get(
          `${API_URL}/api/empleados/${idEmpleado}/nom035`,
          config
        )
      ]);
      setEmpleado(
        respuestaAplicaciones.data?.empleado ||
        respuestaCuestionarios.data?.empleado ||
        null
      );
      setCuestionarios(
        Array.isArray(
          respuestaCuestionarios.data?.cuestionarios
        )
          ? respuestaCuestionarios.data.cuestionarios
          : []
      );
      setAplicaciones(
        Array.isArray(
          respuestaAplicaciones.data?.aplicaciones
        )
          ? respuestaAplicaciones.data.aplicaciones
          : []
      );
    } catch (err) {
      console.error(
        "❌ Error cargando NOM-035:",
        err
      );
      setError(
        err.response?.data?.message ||
        err.message ||
        "No fue posible cargar el módulo NOM-035."
      );
    } finally {
      setCargando(false);
    }
  }, [
    idEmpleado,
    config,
    token
  ]);
  useEffect(() => {
    cargarDatos();
  }, [cargarDatos]);
  // ==================================================
  // RESUMEN
  // ==================================================
  const aplicacionesPendientes =
    useMemo(
      () =>
        aplicaciones.filter(
          item =>
            item.estatus === "habilitada" ||
            item.estatus === "iniciada"
        ),
      [aplicaciones]
    );
  const aplicacionesCompletadas =
    useMemo(
      () =>
        aplicaciones.filter(
          item =>
            item.estatus === "completada"
        ),
      [aplicaciones]
    );
  const aplicacionesCanceladas =
    useMemo(
      () =>
        aplicaciones.filter(
          item =>
            item.estatus === "cancelada"
        ),
      [aplicaciones]
    );
  const aplicacionesAltoRiesgo =
    useMemo(
      () =>
        aplicaciones.filter(
          item =>
            item.estatus === "completada" &&
            [
              "alto",
              "muy_alto"
            ].includes(
              String(
                item.nivel_riesgo || ""
              ).toLowerCase()
            )
        ),
      [aplicaciones]
    );
  // ==================================================
  // FORMULARIO
  // ==================================================
  const cambiarCampo = e => {
    const {
      name,
      value
    } = e.target;
    setForm(
      prev => ({
        ...prev,
        [name]: value
      })
    );
    setError("");
    setMensaje("");
  };
  // ==================================================
  // HABILITAR
  // ==================================================
  const habilitarCuestionario =
    async e => {
      e.preventDefault();
      const idCuestionario =
        Number(
          form.id_cuestionario
        );
      if (
        !Number.isInteger(
          idCuestionario
        ) ||
        idCuestionario <= 0
      ) {
        setError(
          "Selecciona un cuestionario NOM-035."
        );
        return;
      }
      try {
        setHabilitando(true);
        setError("");
        setMensaje("");
        const respuesta =
          await axios.post(
            `${API_URL}/api/empleados/${idEmpleado}/nom035/habilitar`,
            {
              id_cuestionario:
                idCuestionario,
              tipo_aplicacion:
                form.tipo_aplicacion,
              motivo:
                String(
                  form.motivo || ""
                ).trim() ||
                null
            },
            config
          );
        setMensaje(
          respuesta.data?.message ||
          "Cuestionario NOM-035 habilitado correctamente."
        );
        setForm({
          id_cuestionario: "",
          tipo_aplicacion:
            "periodica",
          motivo: ""
        });
        await cargarDatos();
      } catch (err) {
        console.error(
          "❌ Error habilitando NOM-035:",
          err
        );
        setError(
          err.response?.data?.message ||
          "No fue posible habilitar el cuestionario."
        );
      } finally {
        setHabilitando(false);
      }
    };
  // ==================================================
  // CANCELAR
  // ==================================================
  const cancelarAplicacion =
    async idAplicacion => {
      const confirmar =
        window.confirm(
          "¿Deseas cancelar esta aplicación NOM-035? La aplicación permanecerá registrada en el historial."
        );
      if (!confirmar) {
        return;
      }
      try {
        setProcesandoId(
          idAplicacion
        );
        setError("");
        setMensaje("");
        const respuesta =
          await axios.put(
            `${API_URL}/api/empleados/${idEmpleado}/nom035/${idAplicacion}/cancelar`,
            {},
            config
          );
        setMensaje(
          respuesta.data?.message ||
          "Aplicación cancelada correctamente."
        );
        await cargarDatos();
      } catch (err) {
        console.error(
          "❌ Error cancelando aplicación NOM-035:",
          err
        );
        setError(
          err.response?.data?.message ||
          "No fue posible cancelar la aplicación."
        );
      } finally {
        setProcesandoId(null);
      }
    };

// ==================================================
// ELIMINAR APLICACIÓN CANCELADA
// ==================================================

const eliminarAplicacion =
  async idAplicacion => {

    const confirmar =
      window.confirm(
        "¿Deseas eliminar definitivamente esta aplicación cancelada? Esta acción no se puede deshacer."
      );

    if (!confirmar) {
      return;
    }

    try {
      setProcesandoId(
        idAplicacion
      );

      setError("");
      setMensaje("");

      const respuesta =
        await axios.delete(
          `${API_URL}/api/empleados/${idEmpleado}/nom035/${idAplicacion}`,
          config
        );

      setMensaje(
        respuesta.data?.message ||
        "Aplicación eliminada correctamente."
      );

      setAplicacionesAbiertas(
        prev => {
          const copia = {
            ...prev
          };

          delete copia[
            idAplicacion
          ];

          return copia;
        }
      );

      await cargarDatos();

    } catch (err) {
      console.error(
        "❌ Error eliminando aplicación NOM-035:",
        err
      );

      setError(
        err.response?.data?.message ||
        "No fue posible eliminar la aplicación."
      );

    } finally {
      setProcesandoId(null);
    }
  };

  // ==================================================
  // COPIAR ENLACE
  // ==================================================
  const copiarEnlace =
    async tokenPublico => {
      const enlace =
        `${window.location.origin}/nom035/${tokenPublico}`;
      try {
        await navigator.clipboard
          .writeText(
            enlace
          );
        setMensaje(
          "Enlace NOM-035 copiado correctamente."
        );
        setError("");
      } catch (err) {
        console.error(
          "❌ Error copiando enlace:",
          err
        );
        setError(
          "No fue posible copiar el enlace."
        );
      }
    };
  // ==================================================
  // FECHAS
  // ==================================================
  const formatearFecha =
    fecha => {
      if (!fecha) {
        return "Sin fecha";
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
      return date.toLocaleString(
        "es-MX",
        {
          dateStyle:
            "medium",
          timeStyle:
            "short"
        }
      );
    };
  // ==================================================
  // TIPO APLICACIÓN
  // ==================================================
  const textoTipoAplicacion =
    tipo => {
      const tipos = {
        inicial:
          "Inicial",
        periodica:
          "Periódica",
        seguimiento:
          "Seguimiento",
        extraordinaria:
          "Extraordinaria"
      };
      return (
        tipos[tipo] ||
        tipo ||
        "Aplicación"
      );
    };
  // ==================================================
  // TIPO CUESTIONARIO
  // ==================================================
  const textoTipoCuestionario =
    tipo => {
      const tipos = {
        acontecimiento_traumatico:
          "Acontecimiento traumático severo",
        factores_riesgo:
          "Factores de riesgo psicosocial",
        factores_riesgo_entorno:
          "Factores de riesgo psicosocial y entorno organizacional"
      };
      return (
        tipos[tipo] ||
        tipo ||
        "NOM-035"
      );
    };
  // ==================================================
  // INFORMACIÓN OFICIAL NOM-035
  // ==================================================
  const informacionGuias = {
    I: {
      titulo:
        "Guía I — Acontecimientos traumáticos severos",
      texto:
        "Permite identificar a trabajadores que estuvieron expuestos a acontecimientos traumáticos severos y determinar si corresponde continuar con la evaluación de síntomas asociados."
    },
    II: {
      titulo:
        "Guía II — Factores de riesgo psicosocial",
      texto:
        "Se utiliza para identificar y analizar factores de riesgo psicosocial. Es la guía de referencia aplicable para centros de trabajo que tienen entre 16 y 50 trabajadores."
    },
    III: {
      titulo:
        "Guía III — Factores de riesgo psicosocial y entorno organizacional",
      texto:
        "Permite identificar y analizar factores de riesgo psicosocial y evaluar el entorno organizacional. Es la guía de referencia aplicable para centros de trabajo con más de 50 trabajadores."
    }
  };
  const FUENTE_OFICIAL_NOM035 =
    "https://sidof.segob.gob.mx/notas/docFuente/5541828";
  const INFORMACION_STPS_NOM035 =
    "https://www.gob.mx/stps/articulos/norma-oficial-mexicana-nom-035-stps-2018-factores-de-riesgo-psicosocial-en-el-trabajo-identificacion-analisis-y-prevencion";
  // ==================================================
  // ESTADO
  // ==================================================
  const obtenerEstado =
    estatus => {
      const estados = {
        habilitada: {
          texto:
            "Pendiente",
          fondo:
            "#fff7e6",
          color:
            "#b7791f"
        },
        iniciada: {
          texto:
            "Iniciada",
          fondo:
            "#eef4ff",
          color:
            "#2167d5"
        },
        completada: {
          texto:
            "Completada",
          fondo:
            "#ecfdf3",
          color:
            "#067647"
        },
        cancelada: {
          texto:
            "Cancelada",
          fondo:
            "#f2f4f7",
          color:
            "#667085"
        }
      };
      return (
        estados[
          String(
            estatus || ""
          ).toLowerCase()
        ] ||
        estados.habilitada
      );
    };
  // ==================================================
  // NIVEL DE RIESGO
  // ==================================================
  const textoNivelRiesgo =
    nivel => {
      if (!nivel) {
        return "Pendiente de cálculo";
      }
      const niveles = {
        nulo:
          "Nulo",
        bajo:
          "Bajo",
        medio:
          "Medio",
        alto:
          "Alto",
        muy_alto:
          "Muy alto",
        no_aplica:
          "No aplica"
      };
      return (
        niveles[nivel] ||
        nivel
      );
    };
  const estiloRiesgo =
    nivel => {
      const valor =
        String(
          nivel || ""
        ).toLowerCase();
      if (
        valor === "muy_alto"
      ) {
        return {
          background:
            "#fef3f2",
          color:
            "#b42318",
          border:
            "1px solid #fecdca"
        };
      }
      if (
        valor === "alto"
      ) {
        return {
          background:
            "#fff4ed",
          color:
            "#c4320a",
          border:
            "1px solid #ffd6ae"
        };
      }
      if (
        valor === "medio"
      ) {
        return {
          background:
            "#fffaeb",
          color:
            "#b54708",
          border:
            "1px solid #fedf89"
        };
      }
      if (
        valor === "bajo"
      ) {
        return {
          background:
            "#f0fdf4",
          color:
            "#15803d",
          border:
            "1px solid #bbf7d0"
        };
      }
      if (
        valor === "nulo"
      ) {
        return {
          background:
            "#ecfdf3",
          color:
            "#067647",
          border:
            "1px solid #abefc6"
        };
      }
      return {
        background:
          "#f2f4f7",
        color:
          "#475467",
        border:
          "1px solid #d0d5dd"
      };
    };
  // ==================================================
  // PARSEAR JSON
  // ==================================================
  const parsearJSON =
    valor => {
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
  // GUÍA I: CRITERIO Y PRESENTACIÓN
  // ==================================================
  const esGuiaI =
    aplicacion =>
      String(
        aplicacion?.guia || ""
      ).trim() === "I";
  const requiereValoracionClinica =
    aplicacion =>
      esGuiaI(
        aplicacion
      ) &&
      Number(
        aplicacion?.requiere_accion || 0
      ) === 1;
  const textoCriterioGuiaI =
    aplicacion =>
      requiereValoracionClinica(
        aplicacion
      )
        ? "Requiere valoración clínica"
        : "No requiere valoración clínica";
  // ==================================================
  // CARGANDO
  // ==================================================
  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.container}>
          <div style={styles.card}>
            <h2>
              📋 NOM-035
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
  // VISTA
  // ==================================================
  return (
    <div style={styles.page}>
      <div style={styles.container}>
        {/* VOLVER */}
        <button
          type="button"
          style={styles.backButton}
          onClick={() =>
            navigate(
              `/empleado/${idEmpleado}`
            )
          }
        >
          ← Volver al empleado
        </button>
        {/* ENCABEZADO */}
        <div style={styles.header}>
          <div>
            <h1 style={styles.title}>
              📋 NOM-035
            </h1>
            <p style={styles.subtitle}>
              Administración independiente de
              aplicaciones NOM-035, cuestionarios,
              enlaces, resultados y seguimiento de
              factores de riesgo psicosocial.
            </p>
          </div>
        </div>
        {/* EMPLEADO */}
        {empleado && (
          <div style={styles.employeeCard}>
            <div style={styles.avatar}>
              {
                empleado.nombre
                  ?.charAt(0)
                  ?.toUpperCase() ||
                "E"
              }
            </div>
            <div style={{ flex: 1 }}>
              <h2 style={styles.employeeName}>
                {empleado.nombre}
              </h2>
              <div style={styles.meta}>
                🆔{" "}
                {
                  empleado.id_mirror ||
                  "Sin ID MirrorSoul"
                }
              </div>
              <div style={styles.meta}>
                💼{" "}
                {
                  empleado.puesto ||
                  "Puesto no especificado"
                }
              </div>
              <div style={styles.meta}>
                Departamento:{" "}
                <strong>
                  {
                    empleado.departamento ||
                    "No especificado"
                  }
                </strong>
              </div>
            </div>
          </div>
        )}
        {/* INFORMACIÓN */}
        <div style={styles.notice}>
          <strong>
            ℹ️ Módulo independiente NOM-035
          </strong>
          <p style={styles.noticeText}>
            Las aplicaciones NOM-035 mantienen
            sus propios cuestionarios, respuestas,
            resultados e historial. No se mezclan
            con las evaluaciones psicométricas
            generales, Bienestar ni el expediente
            psicológico del empleado.
          </p>
        </div>
        {/* QUÉ ES NOM-035 */}
        <div style={styles.nomInfoCard}>
          <div style={styles.nomInfoHeader}>
            <div>
              <div style={styles.nomEyebrow}>
                NOM-035-STPS-2018
              </div>
              <h2 style={styles.nomInfoTitle}>
                ¿Qué es y para qué sirve?
              </h2>
            </div>
            <div style={styles.nomHeaderActions}>
              <div style={styles.nomShield}>
                🛡️
              </div>
              <button
                type="button"
                style={styles.expandButton}
                onClick={() =>
                  setInfoNomAbierta(prev => !prev)
                }
              >
                {infoNomAbierta
                  ? "▲ Ocultar"
                  : "▼ Ver información"}
              </button>
            </div>
          </div>
          {!infoNomAbierta && (
            <p style={styles.collapsedDescription}>
              Información general, alcance, Guías I, II y III y fuentes oficiales.
            </p>
          )}
          {infoNomAbierta && (
            <>
          <p style={styles.nomInfoText}>
            La NOM-035-STPS-2018 establece elementos
            para identificar, analizar y prevenir los
            factores de riesgo psicosocial, así como
            para promover un entorno organizacional
            favorable en los centros de trabajo.
          </p>
          <div style={styles.nomScopeGrid}>
            <div style={styles.nomScopeItem}>
              <strong>
                Hasta 15 trabajadores
              </strong>
              <span style={styles.nomScopeText}>
                Aplican las obligaciones preventivas
                previstas por la Norma; no se exige la
                identificación mediante Guía II o III.
              </span>
            </div>
            <div style={styles.nomScopeItem}>
              <strong>
                De 16 a 50 trabajadores
              </strong>
              <span style={styles.nomScopeText}>
                Se realiza la identificación y análisis
                de los factores de riesgo psicosocial.
                La Guía II es el instrumento de referencia.
              </span>
            </div>
            <div style={styles.nomScopeItem}>
              <strong>
                Más de 50 trabajadores
              </strong>
              <span style={styles.nomScopeText}>
                Se identifican y analizan los factores
                de riesgo psicosocial y además se evalúa
                el entorno organizacional. La Guía III
                es el instrumento de referencia.
              </span>
            </div>
          </div>
          <div style={styles.guideInfoGrid}>
            {Object.entries(
              informacionGuias
            ).map(
              ([guia, info]) => (
                <div
                  key={guia}
                  style={styles.guideInfoCard}
                >
                  <div style={styles.guideInfoBadge}>
                    Guía {guia}
                  </div>
                  <strong>
                    {info.titulo}
                  </strong>
                  <p style={styles.guideInfoText}>
                    {info.texto}
                  </p>
                </div>
              )
            )}
          </div>
          <div style={styles.nomInfoFoot}>
            Los resultados orientan acciones preventivas
            y de intervención laboral. No constituyen por
            sí mismos un diagnóstico médico o psicológico.
          </div>
          <div style={styles.officialSources}>
            <div>
              <strong>
                📚 Fuentes oficiales
              </strong>
              <p style={styles.officialSourceText}>
                La Guía de Referencia I forma parte de la
                propia NOM-035-STPS-2018. Ahí puedes consultar
                el cuestionario, sus criterios y el resto de
                las Guías de Referencia.
              </p>
            </div>
            <div style={styles.officialSourceActions}>
              <a
                href={FUENTE_OFICIAL_NOM035}
                target="_blank"
                rel="noreferrer"
                style={styles.officialButton}
              >
                📖 Ver NOM-035 oficial
              </a>
              <a
                href={INFORMACION_STPS_NOM035}
                target="_blank"
                rel="noreferrer"
                style={styles.secondaryOfficialButton}
              >
                ℹ️ Información STPS
              </a>
            </div>
          </div>
            </>
          )}
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
        {/* RESUMEN */}
        <div style={styles.summaryGrid}>
          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              📋
            </div>
            <div style={styles.summaryNumber}>
              {aplicaciones.length}
            </div>
            <div style={styles.summaryLabel}>
              Aplicaciones
            </div>
            <small style={styles.summaryDetail}>
              Historial total
            </small>
          </div>
          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              ⏳
            </div>
            <div style={styles.summaryNumber}>
              {
                aplicacionesPendientes.length
              }
            </div>
            <div style={styles.summaryLabel}>
              Pendientes
            </div>
            <small style={styles.summaryDetail}>
              Por responder
            </small>
          </div>
          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              ✅
            </div>
            <div style={styles.summaryNumber}>
              {
                aplicacionesCompletadas.length
              }
            </div>
            <div style={styles.summaryLabel}>
              Completadas
            </div>
            <small style={styles.summaryDetail}>
              Con respuesta final
            </small>
          </div>
          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              ⚪
            </div>
            <div style={styles.summaryNumber}>
              {
                aplicacionesCanceladas.length
              }
            </div>
            <div style={styles.summaryLabel}>
              Canceladas
            </div>
            <small style={styles.summaryDetail}>
              Conservadas en historial
            </small>
          </div>
          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              ⚠️
            </div>
            <div style={styles.summaryNumber}>
              {
                aplicacionesAltoRiesgo.length
              }
            </div>
            <div style={styles.summaryLabel}>
              Atención
            </div>
            <small style={styles.summaryDetail}>
              Riesgo alto o muy alto
            </small>
          </div>
        </div>
        {/* NUEVA APLICACIÓN */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div>
              <h2 style={styles.cardTitle}>
                ➕ Nueva aplicación
              </h2>
              <p style={styles.cardSubtitle}>
                Selecciona la guía correspondiente
                y genera un enlace individual para
                que el empleado responda.
              </p>
            </div>
          </div>
          <form
            onSubmit={
              habilitarCuestionario
            }
          >
            <div style={styles.gridTwo}>
              <div style={styles.field}>
                <label style={styles.label}>
                  Cuestionario *
                </label>
                <select
                  name="id_cuestionario"
                  value={
                    form.id_cuestionario
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >
                  <option value="">
                    Selecciona un cuestionario
                  </option>
                  {
                    cuestionarios.map(
                      cuestionario => (
                        <option
                          key={
                            cuestionario.id_cuestionario
                          }
                          value={
                            cuestionario.id_cuestionario
                          }
                        >
                          Guía{" "}
                          {cuestionario.guia}
                          {" - "}
                          {cuestionario.nombre}
                        </option>
                      )
                    )
                  }
                </select>
              </div>
              <div style={styles.field}>
                <label style={styles.label}>
                  Tipo de aplicación
                </label>
                <select
                  name="tipo_aplicacion"
                  value={
                    form.tipo_aplicacion
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >
                  <option value="inicial">
                    Inicial
                  </option>
                  <option value="periodica">
                    Periódica
                  </option>
                  <option value="seguimiento">
                    Seguimiento
                  </option>
                  <option value="extraordinaria">
                    Extraordinaria
                  </option>
                </select>
              </div>
            </div>
            {
              form.id_cuestionario &&
              (() => {
                const cuestionario =
                  cuestionarios.find(
                    item =>
                      Number(
                        item.id_cuestionario
                      ) ===
                      Number(
                        form.id_cuestionario
                      )
                  );
                if (!cuestionario) {
                  return null;
                }
                return (
                  <div
                    style={
                      styles.questionnaireInfo
                    }
                  >
                    <div style={styles.guideBadge}>
                      Guía{" "}
                      {cuestionario.guia}
                    </div>
                    <strong>
                      {
                        cuestionario.nombre
                      }
                    </strong>
                    {
                      cuestionario.descripcion && (
                        <p style={styles.text}>
                          {
                            cuestionario.descripcion
                          }
                        </p>
                      )
                    }
                    <small style={styles.meta}>
                      {
                        textoTipoCuestionario(
                          cuestionario.tipo
                        )
                      }
                    </small>
                  </div>
                );
              })()
            }
            <div style={styles.field}>
              <label style={styles.label}>
                Motivo de aplicación
              </label>
              <textarea
                name="motivo"
                value={
                  form.motivo
                }
                onChange={
                  cambiarCampo
                }
                style={styles.textarea}
                rows={3}
                placeholder="Ej. Aplicación inicial, revisión periódica, seguimiento o aplicación extraordinaria..."
              />
            </div>
            <div style={styles.applicationNotice}>
              <strong>
                🔗 Se generará un enlace individual
              </strong>
              <p style={styles.noticeText}>
                El empleado podrá abrir el
                cuestionario mediante el enlace
                generado. Sus respuestas se
                conservarán dentro de esta
                aplicación NOM-035.
              </p>
            </div>
            <div style={styles.actions}>
              <button
                type="submit"
                disabled={
                  habilitando ||
                  cuestionarios.length === 0
                }
                style={{
                  ...styles.primaryButton,
                  opacity:
                    habilitando ||
                    cuestionarios.length === 0
                      ? 0.65
                      : 1
                }}
              >
                {
                  habilitando
                    ? "Generando..."
                    : "🔗 Habilitar cuestionario"
                }
              </button>
            </div>
          </form>
        </div>
        {/* HISTORIAL */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div>
              <h2 style={styles.cardTitle}>
                📚 Historial NOM-035
              </h2>
              <p style={styles.cardSubtitle}>
                Consulta aplicaciones pendientes,
                completadas y canceladas del
                empleado.
              </p>
            </div>
            <div style={styles.counter}>
              {aplicaciones.length}
            </div>
          </div>
          {
            aplicaciones.length === 0 ? (
              <div style={styles.empty}>
                <div style={styles.emptyIcon}>
                  📋
                </div>
                <h3>
                  Sin aplicaciones NOM-035
                </h3>
                <p>
                  Todavía no se ha habilitado
                  ningún cuestionario NOM-035
                  para este empleado.
                </p>
              </div>
            ) : (
              <div style={styles.list}>
                {
                  aplicaciones.map(
                    aplicacion => {
                      const estado =
                        obtenerEstado(
                          aplicacion.estatus
                        );
                      const enlace =
                        `${window.location.origin}/nom035/${aplicacion.token_publico}`;
                      const categorias =
                        parsearJSON(
                          aplicacion.categorias
                        );
                      const dominios =
                        parsearJSON(
                          aplicacion.dominios
                        );
                      const riesgoStyle =
                        estiloRiesgo(
                          aplicacion.nivel_riesgo
                        );
                      const aplicacionAbierta =
                        Boolean(
                          aplicacionesAbiertas[
                            aplicacion.id_aplicacion
                          ]
                        );
                      return (
                        <div
                          key={
                            aplicacion.id_aplicacion
                          }
                          style={{
                            ...styles.applicationCard,
                            ...(aplicacion.estatus ===
                              "cancelada"
                              ? styles.cancelledApplication
                              : {})
                          }}
                        >
                          {/* CABECERA */}
                          <div
                            style={
                              styles.applicationHeader
                            }
                          >
                            <div>
                              <div style={styles.badges}>
                                <span
                                  style={
                                    styles.guideBadge
                                  }
                                >
                                  Guía{" "}
                                  {
                                    aplicacion.guia
                                  }
                                </span>
                                <span
                                  style={
                                    styles.typeBadge
                                  }
                                >
                                  {
                                    textoTipoAplicacion(
                                      aplicacion.tipo_aplicacion
                                    )
                                  }
                                </span>
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
                                {
                                  aplicacion.estatus ===
                                    "completada" &&
                                  !esGuiaI(
                                    aplicacion
                                  ) &&
                                  aplicacion.nivel_riesgo && (
                                    <span
                                      style={{
                                        ...styles.riskBadge,
                                        ...riesgoStyle
                                      }}
                                    >
                                      Riesgo:{" "}
                                      {
                                        textoNivelRiesgo(
                                          aplicacion.nivel_riesgo
                                        )
                                      }
                                    </span>
                                  )
                                }
                                {
                                  aplicacion.estatus ===
                                    "completada" &&
                                  esGuiaI(
                                    aplicacion
                                  ) && (
                                    <span
                                      style={{
                                        ...styles.guideICriterionBadge,
                                        ...(requiereValoracionClinica(
                                          aplicacion
                                        )
                                          ? styles.guideIPositiveBadge
                                          : styles.guideINegativeBadge)
                                      }}
                                    >
                                      {
                                        requiereValoracionClinica(
                                          aplicacion
                                        )
                                          ? "⚠️ Valoración clínica requerida"
                                          : "✅ Sin criterio de valoración clínica"
                                      }
                                    </span>
                                  )
                                }
                              </div>
                              <h3
                                style={
                                  styles.applicationTitle
                                }
                              >
                                {
                                  aplicacion.cuestionario_nombre ||
                                  "Cuestionario NOM-035"
                                }
                              </h3>
                              <div style={styles.meta}>
                                {
                                  textoTipoCuestionario(
                                    aplicacion.cuestionario_tipo
                                  )
                                }
                              </div>
                            </div>
                            <div style={styles.dateText}>
                              {
                                formatearFecha(
                                  aplicacion.fecha_habilitacion
                                )
                              }
                            </div>
                          </div>
                          <div style={styles.expandApplicationRow}>
                            <button
                              type="button"
                              style={styles.expandApplicationButton}
                              onClick={() =>
                                toggleAplicacion(
                                  aplicacion.id_aplicacion
                                )
                              }
                            >
                              {aplicacionAbierta
                                ? "▲ Ocultar detalles"
                                : "▼ Ver detalles"}
                            </button>
                          </div>
                          {aplicacionAbierta && (
                            <>
                          {/* MOTIVO */}
                          {
                            aplicacion.motivo && (
                              <div style={styles.section}>
                                <strong>
                                  Motivo de aplicación
                                </strong>
                                <p style={styles.text}>
                                  {
                                    aplicacion.motivo
                                  }
                                </p>
                              </div>
                            )
                          }
                          {/* ENLACE */}
                          {
                            (
                              aplicacion.estatus ===
                                "habilitada" ||
                              aplicacion.estatus ===
                                "iniciada"
                            ) && (
                              <div style={styles.linkBox}>
                                <strong>
                                  🔗 Enlace para el empleado
                                </strong>
                                <div
                                  style={
                                    styles.linkText
                                  }
                                >
                                  {enlace}
                                </div>
                                <button
                                  type="button"
                                  style={
                                    styles.copyButton
                                  }
                                  onClick={() =>
                                    copiarEnlace(
                                      aplicacion.token_publico
                                    )
                                  }
                                >
                                  📋 Copiar enlace
                                </button>
                              </div>
                            )
                          }
                          {/* RESULTADO */}
                          {
                            aplicacion.estatus ===
                              "completada" && (
                              <div style={styles.resultBox}>
                                <div
                                  style={
                                    styles.resultTitle
                                  }
                                >
                                  ✅ Aplicación completada
                                </div>
                                <div
                                  style={
                                    styles.resultGrid
                                  }
                                >
                                  <div>
                                    <span
                                      style={
                                        styles.smallLabel
                                      }
                                    >
                                      Fecha de finalización
                                    </span>
                                    <strong>
                                      {
                                        formatearFecha(
                                          aplicacion.fecha_completada
                                        )
                                      }
                                    </strong>
                                  </div>
                                  {
                                    esGuiaI(
                                      aplicacion
                                    ) ? (
                                      <>
                                        <div>
                                          <span
                                            style={
                                              styles.smallLabel
                                            }
                                          >
                                            Respuestas "Sí"
                                          </span>
                                          <strong>
                                            {
                                              aplicacion.puntaje_total ??
                                              0
                                            }
                                          </strong>
                                        </div>
                                        <div>
                                          <span
                                            style={
                                              styles.smallLabel
                                            }
                                          >
                                            Criterio Guía I
                                          </span>
                                          <strong
                                            style={
                                              requiereValoracionClinica(
                                                aplicacion
                                              )
                                                ? styles.clinicalRequiredText
                                                : styles.clinicalNotRequiredText
                                            }
                                          >
                                            {
                                              textoCriterioGuiaI(
                                                aplicacion
                                              )
                                            }
                                          </strong>
                                        </div>
                                      </>
                                    ) : (
                                      <>
                                        <div>
                                          <span
                                            style={
                                              styles.smallLabel
                                            }
                                          >
                                            Puntaje acumulado
                                          </span>
                                          <strong>
                                            {
                                              aplicacion.puntaje_total ??
                                              "No disponible"
                                            }
                                          </strong>
                                        </div>
                                        <div>
                                          <span
                                            style={
                                              styles.smallLabel
                                            }
                                          >
                                            Nivel de riesgo
                                          </span>
                                          <strong>
                                            {
                                              textoNivelRiesgo(
                                                aplicacion.nivel_riesgo
                                              )
                                            }
                                          </strong>
                                        </div>
                                      </>
                                    )
                                  }
                                </div>
                                {/* SOLO II Y III */}
                                {
                                  !esGuiaI(
                                    aplicacion
                                  ) &&
                                  !aplicacion.nivel_riesgo && (
                                    <div
                                      style={
                                        styles.pendingCalculation
                                      }
                                    >
                                      <strong>
                                        ⚙️ Calificación pendiente
                                      </strong>
                                      <p
                                        style={
                                          styles.pendingText
                                        }
                                      >
                                        El cuestionario ya
                                        fue respondido y sus
                                        respuestas quedaron
                                        almacenadas. Falta
                                        calcular o registrar
                                        el nivel correspondiente
                                        a esta guía.
                                      </p>
                                    </div>
                                  )
                                }
                                {/* EXPLICACIÓN GUÍA I */}
                                {
                                  esGuiaI(
                                    aplicacion
                                  ) && (
                                    <div
                                      style={
                                        styles.guideIExplanation
                                      }
                                    >
                                      <strong>
                                        📋 ¿Qué significa Guía de Referencia I?
                                      </strong>
                                      <p style={styles.text}>
                                        Es el cuestionario incluido en la
                                        NOM-035-STPS-2018 para identificar
                                        a trabajadores que fueron sujetos a
                                        acontecimientos traumáticos severos
                                        y determinar, con base en sus
                                        respuestas, si requieren valoración
                                        clínica.
                                      </p>
                                      <p
                                        style={
                                          styles.guideIExplanationNote
                                        }
                                      >
                                        En esta guía no se calcula un nivel
                                        de riesgo como "bajo", "medio",
                                        "alto" o "muy alto". Esos niveles se
                                        utilizan en las Guías II y III. En
                                        Guía I el resultado es si se cumple
                                        o no un criterio para valoración
                                        clínica.
                                      </p>
                                      <a
                                        href={
                                          FUENTE_OFICIAL_NOM035
                                        }
                                        target="_blank"
                                        rel="noreferrer"
                                        style={
                                          styles.inlineOfficialLink
                                        }
                                      >
                                        Consultar la Guía de Referencia I en la NOM-035 oficial ↗
                                      </a>
                                    </div>
                                  )
                                }
                                {/* RESULTADO GENERAL */}
                                {
                                  aplicacion.resultado_general && (
                                    <div style={styles.section}>
                                      <strong>
                                        Resultado general
                                      </strong>
                                      <p style={styles.text}>
                                        {
                                          aplicacion.resultado_general
                                        }
                                      </p>
                                    </div>
                                  )
                                }
                                {/* CATEGORÍAS / SECCIONES */}
                                {
                                  categorias.length > 0 && (
                                    <div style={styles.section}>
                                      <strong>
                                        {
                                          esGuiaI(
                                            aplicacion
                                          )
                                            ? "Secciones evaluadas"
                                            : "Categorías"
                                        }
                                      </strong>
                                      {
                                        esGuiaI(
                                          aplicacion
                                        ) && (
                                          <p
                                            style={
                                              styles.categoryHelpText
                                            }
                                          >
                                            Se muestra el número de respuestas
                                            "Sí" registradas en cada sección de
                                            la Guía I.
                                          </p>
                                        )
                                      }
                                      <div
                                        style={
                                          styles.scoreList
                                        }
                                      >
                                        {
                                          categorias.map(
                                            (
                                              categoria,
                                              index
                                            ) => (
                                              <div
                                                key={
                                                  `${categoria.nombre}-${index}`
                                                }
                                                style={
                                                  styles.scoreRow
                                                }
                                              >
                                                <span>
                                                  {
                                                    categoria.nombre
                                                  }
                                                </span>
                                                <div
                                                  style={
                                                    styles.scoreValueGroup
                                                  }
                                                >
                                                  <strong>
                                                    {
                                                      esGuiaI(
                                                        aplicacion
                                                      )
                                                        ? `${Number(
                                                            categoria.respuestas_si ??
                                                            0
                                                          )} Sí`
                                                        : categoria.puntaje
                                                    }
                                                  </strong>
                                                  {
                                                    !esGuiaI(
                                                      aplicacion
                                                    ) &&
                                                    categoria.nivel_riesgo && (
                                                      <span
                                                        style={{
                                                          ...styles.miniRiskBadge,
                                                          ...estiloRiesgo(
                                                            categoria.nivel_riesgo
                                                          )
                                                        }}
                                                      >
                                                        {
                                                          textoNivelRiesgo(
                                                            categoria.nivel_riesgo
                                                          )
                                                        }
                                                      </span>
                                                    )
                                                  }
                                                </div>
                                              </div>
                                            )
                                          )
                                        }
                                      </div>
                                    </div>
                                  )
                                }
                                {/* DOMINIOS II Y III */}
                                {
                                  dominios.length > 0 && (
                                    <div style={styles.section}>
                                      <strong>
                                        Dominios
                                      </strong>
                                      <div
                                        style={
                                          styles.scoreList
                                        }
                                      >
                                        {
                                          dominios.map(
                                            (
                                              dominio,
                                              index
                                            ) => (
                                              <div
                                                key={
                                                  `${dominio.nombre}-${index}`
                                                }
                                                style={
                                                  styles.scoreRow
                                                }
                                              >
                                                <span>
                                                  {
                                                    dominio.nombre
                                                  }
                                                </span>
                                                <div
                                                  style={
                                                    styles.scoreValueGroup
                                                  }
                                                >
                                                  <strong>
                                                    {
                                                      dominio.puntaje
                                                    }
                                                  </strong>
                                                  {
                                                    dominio.nivel_riesgo && (
                                                      <span
                                                        style={{
                                                          ...styles.miniRiskBadge,
                                                          ...estiloRiesgo(
                                                            dominio.nivel_riesgo
                                                          )
                                                        }}
                                                      >
                                                        {
                                                          textoNivelRiesgo(
                                                            dominio.nivel_riesgo
                                                          )
                                                        }
                                                      </span>
                                                    )
                                                  }
                                                </div>
                                              </div>
                                            )
                                          )
                                        }
                                      </div>
                                    </div>
                                  )
                                }
                                {/* RECOMENDACIONES */}
                                {
                                  aplicacion.recomendaciones && (
                                    <div
                                      style={
                                        styles.recommendationBox
                                      }
                                    >
                                      <strong>
                                        📌 Recomendaciones
                                      </strong>
                                      <p style={styles.text}>
                                        {
                                          aplicacion.recomendaciones
                                        }
                                      </p>
                                    </div>
                                  )
                                }

                                {/* PRE-EVALUACIÓN IA */}
                                {
                                  aplicacion.preevaluacion_ia ? (
                                    <div
                                      style={
                                        styles.aiEvaluationBox
                                      }
                                    >
                                      <div
                                        style={
                                          styles.aiEvaluationHeader
                                        }
                                      >
                                        <div>
                                          <div
                                            style={
                                              styles.aiEvaluationEyebrow
                                            }
                                          >
                                            🤖 MIRRORSOUL IA
                                          </div>

                                          <strong
                                            style={
                                              styles.aiEvaluationTitle
                                            }
                                          >
                                            Pre-evaluación IA
                                          </strong>
                                        </div>

                                        <span
                                          style={
                                            styles.aiOrientativeBadge
                                          }
                                        >
                                          Orientativa
                                        </span>
                                      </div>

                                      <div
                                        style={
                                          styles.aiEvaluationContent
                                        }
                                      >
                                        {
                                          aplicacion.preevaluacion_ia
                                        }
                                      </div>

                                      <div
                                        style={
                                          styles.aiEvaluationMeta
                                        }
                                      >
                                        {
                                          aplicacion.fecha_preevaluacion_ia && (
                                            <span>
                                              📅{" "}
                                              {
                                                formatearFecha(
                                                  aplicacion.fecha_preevaluacion_ia
                                                )
                                              }
                                            </span>
                                          )
                                        }

                                        {
                                          aplicacion.ia_proveedor && (
                                            <span>
                                              🤖 Proveedor:{" "}
                                              <strong>
                                                {
                                                  aplicacion.ia_proveedor
                                                }
                                              </strong>
                                            </span>
                                          )
                                        }

                                        {
                                          aplicacion.ia_modelo && (
                                            <span>
                                              ⚙️ Modelo:{" "}
                                              <strong>
                                                {
                                                  aplicacion.ia_modelo
                                                }
                                              </strong>
                                            </span>
                                          )
                                        }
                                      </div>

                                      <div
                                        style={
                                          styles.aiDisclaimer
                                        }
                                      >
                                        Esta pre-evaluación fue generada
                                        exclusivamente a partir de los
                                        resultados de esta aplicación
                                        NOM-035. Es una herramienta
                                        orientativa para Recursos Humanos
                                        y no constituye un diagnóstico
                                        médico o psicológico.
                                      </div>
                                    </div>
                                  ) : (
                                    <div
                                      style={
                                        styles.aiPendingBox
                                      }
                                    >
                                      <div
                                        style={
                                          styles.aiPendingHeader
                                        }
                                      >
                                        🤖 Pre-evaluación IA
                                      </div>

                                      <p
                                        style={
                                          styles.aiPendingText
                                        }
                                      >
                                        Esta aplicación no cuenta con una
                                        pre-evaluación IA registrada.
                                      </p>
                                    </div>
                                  )
                                }

                                <div
                                  style={
                                    styles.resultDisclaimer
                                  }
                                >
                                  Este resultado corresponde
                                  exclusivamente a la aplicación
                                  NOM-035 y no representa por sí
                                  mismo un diagnóstico médico o
                                  psicológico.
                                </div>
                              </div>
                            )
                          }
                          {/* CANCELADA */}
                          {
                          aplicacion.estatus ===
                          "cancelada" && (

                           <>
                          <div
                          style={
                          styles.cancelledBox
                          }
                          >

                          <strong>
                        ⚪ Aplicación cancelada
                          </strong>

                          <p
                          style={
                          styles.cancelledText
                           }
                            >
                          Esta aplicación fue cancelada.
                          Puedes conservarla en el historial
                          o eliminarla definitivamente.
                          </p>

                          </div>

                          <div
                          style={
                          styles.deleteActionRow
                          }
                          >

                          <button
                          type="button"
                          style={
                          styles.deleteButton
                          }
                          disabled={
                          procesandoId ===
                          aplicacion.id_aplicacion
                          }
                          onClick={() =>
                          eliminarAplicacion(
                          aplicacion.id_aplicacion
                          )
                          }
                          >
                          {
                          procesandoId ===
                          aplicacion.id_aplicacion
                          ? "Eliminando..."
                          : "🗑️ Eliminar cancelada"
                          }
                          </button>

                          </div>
                          </>

                            )
                            }
                          {/* CANCELAR */}
                          {
                          (
                          aplicacion.estatus ===
                          "habilitada" ||
                          aplicacion.estatus ===
                                "iniciada"
                            ) && (
                              <div
                                style={
                                  styles.itemActions
                                }
                              >
                                <button
                                  type="button"
                                  style={
                                    styles.cancelButton
                                  }
                                  disabled={
                                    procesandoId ===
                                    aplicacion.id_aplicacion
                                  }
                                  onClick={() =>
                                    cancelarAplicacion(
                                      aplicacion.id_aplicacion
                                    )
                                  }
                                >
                                  {
                                    procesandoId ===
                                    aplicacion.id_aplicacion
                                      ? "Procesando..."
                                      : "Cancelar aplicación"
                                  }
                                </button>
                              </div>
                            )
                          }
                            </>
                          )}
                        </div>
                      );
                    }
                  )
                }
              </div>
            )
          }
        </div>
        {/* AVISO FINAL */}
        <div style={styles.footerNotice}>
          <strong>
            📌 Importante
          </strong>
          <p style={styles.footerText}>
            MirrorSoul conserva cada aplicación
            NOM-035 como un registro independiente,
            con su cuestionario, respuestas,
            resultados e historial. La información
            de este módulo no debe mezclarse con
            diagnósticos clínicos ni con el
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
  page: { minHeight:"100vh", background:"linear-gradient(135deg,#f6f8fb 0%,#fafcff 55%,#eef4fb 100%)", padding:"30px 20px", boxSizing:"border-box" },
  container: { maxWidth:"1100px", margin:"0 auto" },
  backButton: { border:"none", background:"transparent", padding:0, marginBottom:"15px", cursor:"pointer", color:"#344054", fontWeight:"700", fontSize:"14px" },
  header: { marginBottom:"22px" },
  title: { margin:"0 0 7px", fontSize:"30px", color:"#173e70" },
  subtitle: { margin:0, color:"#667085", maxWidth:"780px", lineHeight:1.55 },

  employeeCard: { background:"#fff", borderRadius:"16px", padding:"20px", display:"flex", alignItems:"center", gap:"17px", marginBottom:"18px", boxShadow:"0 4px 18px rgba(0,0,0,.05)", border:"1px solid #e7edf5" },
  avatar: { width:"58px", height:"58px", minWidth:"58px", borderRadius:"50%", background:"#e8eef9", color:"#2167d5", display:"flex", justifyContent:"center", alignItems:"center", fontWeight:"800", fontSize:"25px" },
  employeeName: { margin:"0 0 6px", color:"#173e70" },
  meta: { color:"#667085", fontSize:"13px", marginTop:"4px" },

  notice: { background:"#eff6ff", border:"1px solid #bfdbfe", borderRadius:"12px", padding:"15px", marginBottom:"18px", color:"#1e3a8a" },
  noticeText: { margin:"7px 0 0", lineHeight:1.5 },

  nomInfoCard: { background:"#fff", border:"1px solid #dbe7f5", borderRadius:"16px", padding:"22px", marginBottom:"20px", boxShadow:"0 5px 18px rgba(30,64,120,.05)" },
  nomInfoHeader: { display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:"16px", marginBottom:"12px" },
  nomEyebrow: { display:"inline-block", background:"#eaf2ff", color:"#2167d5", borderRadius:"20px", padding:"5px 10px", fontSize:"12px", fontWeight:"800", marginBottom:"8px" },
  nomInfoTitle: { margin:0, color:"#173e70", fontSize:"22px" },
  nomShield: { fontSize:"30px" },
  nomInfoText: { margin:"0 0 16px", color:"#475467", lineHeight:1.6 },

  nomScopeGrid: { display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))", gap:"12px", marginBottom:"16px" },
  nomScopeItem: { display:"flex", flexDirection:"column", gap:"7px", background:"#f8fafc", border:"1px solid #e4e7ec", borderRadius:"12px", padding:"14px", color:"#344054" },
  nomScopeText: { color:"#667085", fontSize:"13px", lineHeight:1.5 },

  guideInfoGrid: { display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(230px,1fr))", gap:"12px" },
  guideInfoCard: { border:"1px solid #e4e7ec", borderRadius:"12px", padding:"14px", background:"#fff" },
  guideInfoBadge: { display:"inline-block", background:"#f2f4f7", color:"#344054", borderRadius:"20px", padding:"4px 9px", fontSize:"11px", fontWeight:"800", marginBottom:"9px" },
  guideInfoText: { margin:"7px 0 0", color:"#667085", fontSize:"13px", lineHeight:1.5 },
  nomInfoFoot: { marginTop:"15px", padding:"12px", borderRadius:"10px", background:"#fff8e8", color:"#8a5b00", fontSize:"13px", lineHeight:1.5 },

  officialSources: { marginTop:"16px", paddingTop:"16px", borderTop:"1px solid #e4e7ec", display:"flex", justifyContent:"space-between", alignItems:"center", gap:"14px", flexWrap:"wrap" },
  officialSourceText: { margin:"6px 0 0", color:"#667085", fontSize:"13px", lineHeight:1.5, maxWidth:"650px" },
  officialSourceActions: { display:"flex", gap:"8px", flexWrap:"wrap" },
  officialButton: { display:"inline-block", textDecoration:"none", background:"#2563eb", color:"#fff", borderRadius:"9px", padding:"9px 12px", fontSize:"13px", fontWeight:"800" },
  secondaryOfficialButton: { display:"inline-block", textDecoration:"none", background:"#fff", color:"#344054", border:"1px solid #d0d5dd", borderRadius:"9px", padding:"9px 12px", fontSize:"13px", fontWeight:"800" },

  guideICriterionBadge: { padding:"5px 9px", borderRadius:"20px", fontSize:"12px", fontWeight:"800", border:"1px solid" },
  guideIPositiveBadge: { background:"#fff4ed", color:"#b42318", borderColor:"#fecdca" },
  guideINegativeBadge: { background:"#ecfdf3", color:"#067647", borderColor:"#abefc6" },
  clinicalRequiredText: { color:"#b42318" },
  clinicalNotRequiredText: { color:"#067647" },

  guideIExplanation: { marginTop:"15px", background:"#f8fafc", border:"1px solid #d0d5dd", borderRadius:"10px", padding:"14px", color:"#344054" },
  guideIExplanationNote: { margin:"9px 0", color:"#667085", fontSize:"13px", lineHeight:1.5 },
  inlineOfficialLink: { display:"inline-block", marginTop:"4px", color:"#175cd3", fontWeight:"800", fontSize:"13px", textDecoration:"none" },
  categoryHelpText: { margin:"6px 0 0", color:"#667085", fontSize:"12px", lineHeight:1.5 },

  collapsedDescription: { margin:"7px 0 0", color:"#667085", fontSize:"13px", lineHeight:1.5 },
  nomHeaderActions: { display:"flex", alignItems:"center", gap:"10px", flexWrap:"wrap", justifyContent:"flex-end" },
  expandButton: { border:"1px solid #d0d5dd", background:"#fff", color:"#344054", borderRadius:"9px", padding:"9px 13px", cursor:"pointer", fontWeight:"800", whiteSpace:"nowrap" },
  expandApplicationRow: { display:"flex", justifyContent:"flex-end", marginTop:"12px" },
  expandApplicationButton: { border:"1px solid #d0d5dd", background:"#f8fafc", color:"#344054", borderRadius:"9px", padding:"8px 13px", cursor:"pointer", fontWeight:"800", fontSize:"13px" },

  success: { background:"#ecfdf3", border:"1px solid #abefc6", color:"#067647", borderRadius:"10px", padding:"13px", marginBottom:"18px" },
  error: { background:"#fef3f2", border:"1px solid #fecdca", color:"#b42318", borderRadius:"10px", padding:"13px", marginBottom:"18px" },

  summaryGrid: { display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))", gap:"12px", marginBottom:"22px" },
  summaryCard: { background:"#fff", border:"1px solid #e4ebf4", borderRadius:"15px", padding:"16px", textAlign:"center", boxShadow:"0 5px 16px rgba(30,64,120,.05)" },
  summaryIcon: { fontSize:"22px", marginBottom:"5px" },
  summaryNumber: { fontSize:"25px", fontWeight:"900", color:"#173e70" },
  summaryLabel: { marginTop:"3px", fontSize:"13px", fontWeight:"800", color:"#344054" },
  summaryDetail: { display:"block", marginTop:"5px", color:"#667085" },

  card: { background:"#fff", borderRadius:"16px", padding:"24px", marginBottom:"22px", boxShadow:"0 4px 18px rgba(0,0,0,.05)", border:"1px solid #e7edf5" },
  cardHeader: { display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:"15px", marginBottom:"20px" },
  cardTitle: { margin:"0 0 5px", color:"#173e70" },
  cardSubtitle: { margin:0, color:"#667085", lineHeight:1.5 },

  gridTwo: { display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(240px,1fr))", gap:"16px" },
  field: { marginBottom:"18px" },
  label: { display:"block", fontWeight:"700", marginBottom:"7px", color:"#344054" },
  input: { width:"100%", boxSizing:"border-box", border:"1px solid #d0d5dd", borderRadius:"10px", padding:"11px 12px", background:"#fff", fontSize:"15px" },
  textarea: { width:"100%", boxSizing:"border-box", border:"1px solid #d0d5dd", borderRadius:"10px", padding:"12px", resize:"vertical", fontFamily:"inherit", fontSize:"15px", lineHeight:1.5 },

  questionnaireInfo: { background:"#f8fafc", border:"1px solid #e4e7ec", borderRadius:"12px", padding:"15px", marginBottom:"18px" },
  applicationNotice: { background:"#f8fafc", border:"1px solid #e4e7ec", borderRadius:"10px", padding:"13px", marginBottom:"18px", color:"#475467" },

  actions: { display:"flex", justifyContent:"flex-end" },
  primaryButton: { border:"none", borderRadius:"10px", background:"#2563eb", color:"#fff", padding:"11px 17px", cursor:"pointer", fontWeight:"700" },

  counter: { minWidth:"42px", height:"42px", borderRadius:"10px", background:"#eef2f7", color:"#344054", display:"flex", justifyContent:"center", alignItems:"center", fontWeight:"800" },

  list: { display:"flex", flexDirection:"column", gap:"16px" },
  applicationCard: { border:"1px solid #e4e7ec", borderRadius:"14px", padding:"18px", background:"#fff" },
  cancelledApplication: { opacity:.8, background:"#fafafa" },
  applicationHeader: { display:"flex", justifyContent:"space-between", alignItems:"flex-start", flexWrap:"wrap", gap:"12px" },

  badges: { display:"flex", flexWrap:"wrap", gap:"7px", marginBottom:"8px" },
  guideBadge: { display:"inline-block", background:"#ede9fe", color:"#5b21b6", padding:"5px 9px", borderRadius:"20px", fontSize:"12px", fontWeight:"800", marginBottom:"5px" },
  typeBadge: { background:"#eef4ff", color:"#3538cd", padding:"5px 9px", borderRadius:"20px", fontSize:"12px", fontWeight:"700" },
  statusBadge: { padding:"5px 9px", borderRadius:"20px", fontSize:"12px", fontWeight:"700" },
  riskBadge: { padding:"5px 9px", borderRadius:"20px", fontSize:"12px", fontWeight:"800" },

  applicationTitle: { margin:0, fontSize:"18px", color:"#173e70" },
  dateText: { color:"#667085", fontSize:"13px" },
  section: { marginTop:"15px" },
  text: { margin:"6px 0 0", whiteSpace:"pre-wrap", lineHeight:1.55, color:"#344054" },

  linkBox: { marginTop:"16px", background:"#f8fafc", border:"1px solid #e4e7ec", borderRadius:"10px", padding:"14px" },
  linkText: { wordBreak:"break-all", color:"#475467", fontSize:"13px", margin:"7px 0 10px" },
  copyButton: { border:"1px solid #d0d5dd", background:"#fff", borderRadius:"8px", padding:"8px 11px", cursor:"pointer", fontWeight:"700" },

  resultBox: { marginTop:"16px", background:"#f0fdf4", border:"1px solid #bbf7d0", borderRadius:"10px", padding:"15px" },
  resultTitle: { fontWeight:"800", color:"#166534", marginBottom:"12px" },
  resultGrid: { display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))", gap:"12px" },
  smallLabel: { display:"block", color:"#667085", fontSize:"12px", marginBottom:"4px" },

  pendingCalculation: { background:"#fff7ed", border:"1px solid #fed7aa", borderRadius:"10px", padding:"13px", marginTop:"15px", color:"#9a3412" },
  pendingText: { margin:"6px 0 0", lineHeight:1.5 },

  scoreList: { marginTop:"9px", display:"flex", flexDirection:"column", gap:"7px" },
  scoreValueGroup: { display:"flex", alignItems:"center", justifyContent:"flex-end", gap:"8px", flexWrap:"wrap" },
  miniRiskBadge: { display:"inline-flex", alignItems:"center", borderRadius:"999px", padding:"3px 8px", fontSize:"10px", fontWeight:"800", whiteSpace:"nowrap" },
  scoreRow: { background:"#fff", border:"1px solid #e4e7ec", borderRadius:"8px", padding:"9px 11px", display:"flex", justifyContent:"space-between", gap:"12px" },

  recommendationBox: { marginTop:"15px", background:"#eff6ff", border:"1px solid #bfdbfe", borderRadius:"10px", padding:"13px" },

  aiEvaluationBox: { marginTop:"16px", background:"linear-gradient(135deg,#f5f3ff 0%,#faf5ff 100%)", border:"1px solid #ddd6fe", borderRadius:"12px", padding:"16px" },
  aiEvaluationHeader: { display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:"12px", flexWrap:"wrap", marginBottom:"14px" },
  aiEvaluationEyebrow: { color:"#7c3aed", fontSize:"11px", fontWeight:"900", letterSpacing:".5px", marginBottom:"4px" },
  aiEvaluationTitle: { color:"#4c1d95", fontSize:"16px" },
  aiOrientativeBadge: { background:"#ede9fe", color:"#6d28d9", border:"1px solid #ddd6fe", borderRadius:"999px", padding:"5px 9px", fontSize:"11px", fontWeight:"800" },
  aiEvaluationContent: { whiteSpace:"pre-wrap", lineHeight:1.65, color:"#344054", fontSize:"14px", background:"#fff", border:"1px solid #ede9fe", borderRadius:"9px", padding:"14px" },
  aiEvaluationMeta: { display:"flex", flexWrap:"wrap", gap:"8px 16px", marginTop:"12px", color:"#667085", fontSize:"11px" },
  aiDisclaimer: { marginTop:"12px", paddingTop:"10px", borderTop:"1px solid #ddd6fe", color:"#6b7280", fontSize:"11px", lineHeight:1.5 },
  aiPendingBox: { marginTop:"16px", background:"#f8fafc", border:"1px dashed #cbd5e1", borderRadius:"10px", padding:"13px" },
  aiPendingHeader: { fontWeight:"800", color:"#475467" },
  aiPendingText: { margin:"6px 0 0", color:"#667085", fontSize:"13px", lineHeight:1.5 },

  resultDisclaimer: { marginTop:"15px", padding:"11px", borderRadius:"9px", background:"#fff", color:"#667085", fontSize:"12px", lineHeight:1.5 },

  cancelledBox: { marginTop:"15px", background:"#f2f4f7", border:"1px solid #d0d5dd", borderRadius:"10px", padding:"13px", color:"#475467" },
  cancelledText: { margin:"6px 0 0", lineHeight:1.5 },

  itemActions: { display:"flex", justifyContent:"flex-end", marginTop:"15px" },
  cancelButton: { border:"1px solid #fecdca", background:"#fff5f5", color:"#b42318", borderRadius:"8px", padding:"8px 11px", cursor:"pointer", fontWeight:"700" },

  deleteActionRow: { display:"flex", justifyContent:"flex-end", marginTop:"12px" },
  deleteButton: { border:"1px solid #fda29b", background:"#fef3f2", color:"#b42318", borderRadius:"9px", padding:"9px 13px", cursor:"pointer", fontWeight:"800", fontSize:"13px" },

  empty: { textAlign:"center", padding:"34px", color:"#667085" },
  emptyIcon: { fontSize:"40px" },

  footerNotice: { background:"#fff", borderRadius:"12px", padding:"16px", marginBottom:"25px", border:"1px solid #e4e7ec", boxShadow:"0 3px 14px rgba(0,0,0,.04)" },
  footerText: { margin:"7px 0 0", color:"#667085", lineHeight:1.5 }
};
export default Nom035Empleado;
