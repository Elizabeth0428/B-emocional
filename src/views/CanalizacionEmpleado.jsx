import React, { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import { useNavigate, useParams } from "react-router-dom";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;

const obtenerToken = () =>
  localStorage.getItem("token") ||
  sessionStorage.getItem("token") ||
  "";

const ORIGENES = [
  { value: "nom035", label: "NOM-035" },
  { value: "estres_laboral", label: "Estrés laboral" },
  { value: "otra_prueba", label: "Otra prueba laboral" },
  { value: "entrevista_rh", label: "Entrevista RH" },
  { value: "observacion_rh", label: "Observación RH" }
];

const ORIGENES_MANUALES = [
  { value: "entrevista_rh", label: "Entrevista RH" },
  { value: "observacion_rh", label: "Observación RH" },
  { value: "otra_prueba", label: "Otra evaluación / antecedente laboral" }
];

const TIPOS_SEGUIMIENTO = [
  { value: "contacto", label: "Contacto con el empleado" },
  { value: "recordatorio", label: "Recordatorio" },
  { value: "sin_respuesta", label: "Sin respuesta" },
  { value: "nuevas_opciones", label: "Solicitud / envío de nuevas opciones" },
  { value: "rechazo", label: "Rechazo de canalización" },
  { value: "seguimiento_general", label: "Seguimiento general" }
];

const MOTIVOS_NO_SELECCION = [
  { value: "", label: "Selecciona un motivo" },
  { value: "costo", label: "Costo" },
  { value: "ubicacion", label: "Ubicación" },
  { value: "horario", label: "Horario" },
  { value: "no_interesaron_opciones", label: "No le interesaron las opciones" },
  { value: "prefiere_otro_profesional", label: "Prefiere otro profesional" },
  { value: "no_desea_atencion", label: "No desea recibir atención" },
  { value: "no_respondio", label: "No respondió" },
  { value: "aun_valorando", label: "Aún está valorando las opciones" },
  { value: "otro", label: "Otro" }
];

const etiquetasEstado = {
  pendiente_revision: "Pendiente de revisión",
  opciones_enviadas: "Opciones enviadas",
  pendiente_eleccion: "Pendiente de elección",
  seleccion_realizada: "Selección realizada",
  sin_seleccion: "Sin selección",
  en_seguimiento: "En seguimiento",
  requiere_nuevas_opciones: "Profesional rechazó · requiere nuevas opciones",
  cerrada: "Cerrada",
  cancelada: "Cancelada"
};

const etiquetasRecomendacion = {
  no_requiere: "No requiere canalización",
  seguimiento: "Sugiere seguimiento",
  canalizacion: "Canalización recomendada"
};

const etiquetasDecision = {
  pendiente: "Pendiente de revisión",
  canalizar: "Canalizar",
  seguimiento: "Dar seguimiento",
  no_canalizar: "No canalizar"
};

const formatearFecha = valor => {
  if (!valor) return "—";

  const fecha = new Date(valor);

  if (Number.isNaN(fecha.getTime())) {
    return valor;
  }

  return fecha.toLocaleString("es-MX", {
    dateStyle: "medium",
    timeStyle: "short"
  });
};

const money = valor => {
  if (
    valor === null ||
    valor === undefined ||
    valor === ""
  ) {
    return null;
  }

  const numero = Number(valor);

  if (Number.isNaN(numero)) {
    return valor;
  }

  return numero.toLocaleString("es-MX", {
    style: "currency",
    currency: "MXN"
  });
};

const nombreOrigen = valor =>
  ORIGENES.find(
    item => item.value === valor
  )?.label ||
  valor ||
  "Sin origen";

const parseFactores = valor => {
  if (!valor) return [];

  if (Array.isArray(valor)) {
    return valor;
  }

  if (typeof valor === "object") {
    return Object.entries(valor).map(
      ([clave, dato]) => ({
        clave,
        dato
      })
    );
  }

  try {
    const parsed =
      JSON.parse(valor);

    if (Array.isArray(parsed)) {
      return parsed;
    }

    if (
      parsed &&
      typeof parsed === "object"
    ) {
      return Object.entries(parsed).map(
        ([clave, dato]) => ({
          clave,
          dato
        })
      );
    }
  } catch {}

  return [];
};

const parseAreasRequeridas =
  valor => {
    if (!valor) {
      return [];
    }

    if (Array.isArray(valor)) {
      return valor
        .map(Number)
        .filter(
          item =>
            Number.isInteger(item) &&
            item > 0
        );
    }

    try {
      const parsed =
        JSON.parse(valor);

      return Array.isArray(parsed)
        ? parsed
            .map(Number)
            .filter(
              item =>
                Number.isInteger(item) &&
                item > 0
            )
        : [];
    } catch {
      return [];
    }
  };

function Seccion({
  titulo,
  subtitulo,
  abierta,
  onToggle,
  children,
  alerta = false
}) {
  return (
    <div style={styles.section}>
      <button
        type="button"
        style={{
          ...styles.sectionHeader,
          ...(alerta
            ? styles.sectionHeaderAlert
            : {})
        }}
        onClick={onToggle}
      >
        <div style={styles.sectionTitleWrap}>
          <strong style={styles.sectionTitle}>
            {titulo}
          </strong>

          {subtitulo && (
            <span style={styles.sectionSubtitle}>
              {subtitulo}
            </span>
          )}
        </div>

        <span style={styles.chevron}>
          {abierta ? "▲" : "▼"}
        </span>
      </button>

      {abierta && (
        <div style={styles.sectionBody}>
          {children}
        </div>
      )}
    </div>
  );
}

export default function CanalizacionEmpleado() {
  const params =
    useParams();

  const navigate =
    useNavigate();

  const opcionesRef =
    useRef(null);

  const enlaceRef =
    useRef(null);

  const idEmpleado =
    Number(
      params.idEmpleado ||
      params.id ||
      params.empleadoId
    );

  const [empleado, setEmpleado] =
    useState(null);

  const [canalizaciones, setCanalizaciones] =
    useState([]);

  const [recomendaciones, setRecomendaciones] =
    useState([]);

  const [seleccionadaId, setSeleccionadaId] =
    useState(null);

  const [detalle, setDetalle] =
    useState(null);

  const [profesionales, setProfesionales] =
    useState([]);
  
  const [catalogoAreas, setCatalogoAreas] =
  useState([]);

  const [cargandoProfesionales, setCargandoProfesionales] =
  useState(false);

  const [criteriosRanking, setCriteriosRanking] =
  useState({
    modalidad_atencion_preferida: "",
    areas_atencion_requeridas: []
  });

  const [rankingActivo, setRankingActivo] =
  useState(false);
    
  const [cargando, setCargando] =
    useState(true);

  const [cargandoDetalle, setCargandoDetalle] =
    useState(false);

  const [
    cargandoRecomendaciones,
    setCargandoRecomendaciones
  ] = useState(false);

  const [procesando, setProcesando] =
    useState(false);

  const [mensaje, setMensaje] =
    useState("");

  const [error, setError] =
    useState("");

  const [
    enlaceEmpleado,
    setEnlaceEmpleado
  ] = useState("");

  const [mostrarNueva, setMostrarNueva] =
    useState(false);

  const [nueva, setNueva] =
    useState({
      origen: "observacion_rh",
      id_referencia_origen: "",
      motivo: ""
    });

  const [
    observacionesRecomendacion,
    setObservacionesRecomendacion
  ] = useState({});

  // Solo una recomendación/prueba puede estar abierta a la vez.
  // null = todas compactas.
  const [
    recomendacionAbiertaId,
    setRecomendacionAbiertaId
  ] = useState(null);

  const alternarRecomendacion =
    idRecomendacion => {
      setRecomendacionAbiertaId(
        actual =>
          Number(actual) ===
          Number(idRecomendacion)
            ? null
            : idRecomendacion
      );
    };

  const [
    seleccionProfesionales,
    setSeleccionProfesionales
  ] = useState([]);

  const [seguimiento, setSeguimiento] =
    useState({
      tipo_seguimiento: "contacto",
      motivo_no_seleccion: "",
      observacion: ""
    });

  const [
    cierreObservacion,
    setCierreObservacion
  ] = useState("");

  const [
    motivoCancelacion,
    setMotivoCancelacion
  ] = useState("");

  const [abiertas, setAbiertas] =
    useState({
      recomendaciones: true,
      origen: false,
      profesionales: true,
      eleccion: false,
      seguimiento: false,
      historial: false
    });

  const config =
    useMemo(
      () => ({
        headers: {
          Authorization:
            `Bearer ${obtenerToken()}`
        }
      }),
      []
    );

  const canalizacionSeleccionada =
    canalizaciones.find(
      item =>
        Number(
          item.id_canalizacion
        ) ===
        Number(
          seleccionadaId
        )
    ) || null;


  // ==================================================
  // TIPO DE CANALIZACIÓN
  //
  // SISTEMA:
  // - Las áreas de atención ya vienen determinadas
  //   por la detección que originó la canalización.
  // - RH NO vuelve a seleccionarlas manualmente.
  //
  // RH / MANUAL:
  // - RH sí selecciona las áreas requeridas.
  // ==================================================

  const esCanalizacionSistema =
    detalle?.canalizacion
      ?.tipo_deteccion ===
    "sistema";



  // ==================================================
  // PERFIL PROFESIONAL - AUXILIARES
  // ==================================================

  const obtenerFotoProfesional =
    foto => {
      if (!foto) {
        return "";
      }

      const valor =
        String(foto).trim();

      if (
        valor.startsWith("http://") ||
        valor.startsWith("https://")
      ) {
        return valor;
      }

      return `${API_URL}${valor}`;
    };


  const encontrarProfesionalCatalogo =
    opcion => {

      if (!opcion) {
        return null;
      }

      return profesionales.find(
        profesional => {

          if (
            opcion.tipo_profesional ===
            "mirrorsoul"
          ) {
            return (
              profesional.tipo_profesional ===
                "mirrorsoul" &&

              Number(
                profesional.id_psicologo
              ) ===
                Number(
                  opcion.id_psicologo
                )
            );
          }

          return (
            profesional.tipo_profesional ===
              "externo" &&

            Number(
              profesional.id_profesional_externo
            ) ===
              Number(
                opcion.id_profesional_externo
              )
          );

        }
      ) || null;
    };


  const enriquecerOpcion =
    opcion => {

      const actual =
        encontrarProfesionalCatalogo(
          opcion
        );

      return {
        ...opcion,
        ...(actual || {}),

        nombre:
          actual?.nombre ||
          opcion?.nombre_profesional ||
          opcion?.nombre ||
          "Profesional",

        especialidad:
          actual?.especialidad ||
          opcion?.especialidad ||
          "",

        foto_url:
          actual?.foto_url ||
          opcion?.foto_url ||
          "",

        descripcion:
          actual?.descripcion ||
          opcion?.descripcion ||
          "",

        anos_experiencia:
          actual?.anos_experiencia ??
          opcion?.anos_experiencia ??
          null,

        areas_atencion:
          Array.isArray(
            actual?.areas_atencion
          )
            ? actual.areas_atencion
            : Array.isArray(
                opcion?.areas_atencion
              )
            ? opcion.areas_atencion
            : [],

        modalidad_presencial:
          actual?.modalidad_presencial ??
          opcion?.modalidad_presencial ??
          null,

        modalidad_videollamada:
          actual?.modalidad_videollamada ??
          opcion?.modalidad_videollamada ??
          null,

        precio_presencial:
          actual?.precio_presencial ??
          opcion?.precio_presencial ??
          null,

        precio_videollamada:
          actual?.precio_videollamada ??
          opcion?.precio_videollamada ??
          null,

        estado:
          actual?.estado ||
          opcion?.estado ||
          "",

        municipio:
          actual?.municipio ||
          opcion?.municipio ||
          "",

        colonia:
          actual?.colonia ||
          opcion?.colonia ||
          "",

        disponibilidad:
          actual?.disponibilidad ||
          opcion?.disponibilidad ||
          ""
      };
    };

  const recomendacionesPendientes =
    recomendaciones.filter(
      item =>
        item.decision_rh ===
        "pendiente"
    );

  // ==================================================
  // CARGAR CANALIZACIONES
  // ==================================================

  const cargarCanalizaciones =
    async () => {
      if (!idEmpleado) {
        setError(
          "No se recibió un empleado válido."
        );

        setCargando(false);
        return;
      }

      try {
        setCargando(true);
        setError("");

        const { data } =
          await axios.get(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones`,
            config
          );

        setEmpleado(
          data?.empleado ||
          null
        );

        const lista =
          Array.isArray(
            data?.canalizaciones
          )
            ? data.canalizaciones
            : [];

        setCanalizaciones(
          lista
        );

        if (
          seleccionadaId &&
          !lista.some(
            item =>
              Number(
                item.id_canalizacion
              ) ===
              Number(
                seleccionadaId
              )
          )
        ) {
          setSeleccionadaId(
            null
          );

          setDetalle(
            null
          );
        }

      } catch (err) {
        console.error(
          "❌ Error cargando canalizaciones:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible cargar las canalizaciones."
        );

      } finally {
        setCargando(false);
      }
    };

  // ==================================================
  // CARGAR RECOMENDACIONES DEL SISTEMA
  // ==================================================

  const cargarRecomendaciones =
    async () => {
      if (!idEmpleado) {
        return;
      }

      try {
        setCargandoRecomendaciones(
          true
        );

        const { data } =
          await axios.get(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/recomendaciones`,
            config
          );

        setRecomendaciones(
          Array.isArray(
            data?.recomendaciones
          )
            ? data.recomendaciones
            : []
        );

      } catch (err) {
        console.error(
          "❌ Error cargando recomendaciones:",
          err
        );

        setRecomendaciones(
          []
        );

      } finally {
        setCargandoRecomendaciones(
          false
        );
      }
    };

  // ==================================================
  // CARGAR CATÁLOGO DE ÁREAS
  // ==================================================

  const cargarCatalogoAreas =
    async () => {
      try {
        const { data } =
          await axios.get(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/areas-atencion`,
            config
          );

        setCatalogoAreas(
          Array.isArray(
            data?.areas
          )
            ? data.areas
            : []
        );

      } catch (err) {
        console.error(
          "❌ Error cargando catálogo de áreas:",
          err
        );

        setCatalogoAreas([]);
      }
    };


  // ==================================================
  // CARGAR PROFESIONALES + RANKING
  // ==================================================

  const cargarProfesionales =
    async idCanalizacion => {
      if (
        !idEmpleado ||
        !idCanalizacion
      ) {
        setProfesionales([]);
        setRankingActivo(false);
        return;
      }

      try {
        setCargandoProfesionales(true);
        setError("");

        const { data } =
          await axios.get(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/${idCanalizacion}/psicologos-disponibles`,
            config
          );

        setProfesionales(
          Array.isArray(
            data?.profesionales
          )
            ? data.profesionales
            : []
        );

        setRankingActivo(
          Boolean(
            data?.ranking?.activo
          )
        );

      } catch (err) {
        console.error(
          "❌ Error cargando ranking de profesionales:",
          err
        );

        setProfesionales([]);
        setRankingActivo(false);

        if (
          err.response?.status !==
          409
        ) {
          setError(
            err.response?.data?.message ||
            "No fue posible cargar los profesionales disponibles."
          );
        }

      } finally {
        setCargandoProfesionales(false);
      }
    };

 // ==================================================
// CARGAR DETALLE DE CANALIZACIÓN
// ==================================================

const cargarDetalle =
  async idCanalizacion => {

    try {

      setCargandoDetalle(
        true
      );

      setError("");
      setMensaje("");


      const { data } =
        await axios.get(
          `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/${idCanalizacion}`,
          config
        );


      setSeleccionadaId(
        idCanalizacion
      );


      // ==================================================
      // IMPORTANTE
      //
      // AQUÍ YA NO CARGAMOS directamente
      // seleccionProfesionales.
      //
      // El useEffect de abajo se encargará de comparar
      // las opciones antiguas contra el catálogo actual.
      // ==================================================

      setDetalle(
        data
      );

      const canalizacion =
        data?.canalizacion ||
        null;

      const modalidad =
        canalizacion
          ?.modalidad_atencion_preferida ||
        "";

      const areas =
        parseAreasRequeridas(
          canalizacion
            ?.areas_atencion_requeridas
        );

      setCriteriosRanking({
        modalidad_atencion_preferida:
          modalidad,
        areas_atencion_requeridas:
          areas
      });

      if (
        modalidad &&
        areas.length
      ) {
        await cargarProfesionales(
          idCanalizacion
        );
      } else {
        setProfesionales([]);
        setRankingActivo(false);
      }


    } catch (err) {

      console.error(
        "❌ Error cargando detalle:",
        err
      );


      setError(
        err.response?.data?.message ||
        "No fue posible cargar el detalle de la canalización."
      );


    } finally {

      setCargandoDetalle(
        false
      );

    }

  };


// ==================================================
// CARGA PRINCIPAL
// ==================================================

useEffect(
  () => {

    if (!idEmpleado) {
      return;
    }


    cargarCanalizaciones();

    cargarRecomendaciones();

    cargarCatalogoAreas();

  },
  [
    idEmpleado
  ]
);


// ==================================================
// SINCRONIZAR OPCIONES ENVIADAS
// CON PROFESIONALES ACTUALMENTE DISPONIBLES
//
// EJEMPLO:
//
// Antes:
// Abraham
// Abraham
// Arely
// Liliana
//
// Ahora catálogo autorizado:
// Liliana
//
// Resultado:
// 1/5 seleccionado
// ==================================================

useEffect(
  () => {

    // ==================================================
    // TODAVÍA NO HAY DETALLE
    // ==================================================

    if (
      !detalle ||
      !Array.isArray(
        detalle?.opciones
      )
    ) {

      return;

    }


    // ==================================================
    // TODAVÍA NO TERMINA DE CARGAR EL CATÁLOGO
    // ==================================================

    if (
      !Array.isArray(
        profesionales
      )
    ) {

      return;

    }


    // ==================================================
    // CONVERTIR OPCIONES ANTERIORES
    // ==================================================

    const opcionesAnteriores =
      detalle.opciones
        .filter(
          opcion =>
            Number(
              opcion.enviado
            ) === 1 &&
            ![
              "rechazado",
              "rechazada"
            ].includes(
              String(
                opcion
                  .estado_respuesta_profesional ||
                ""
              )
                .trim()
                .toLowerCase()
            )
        )
        .map(
        opcion => ({

          tipo_profesional:
            opcion.tipo_profesional,

          id_psicologo:
            opcion.id_psicologo
              ? Number(
                  opcion.id_psicologo
                )
              : null,

          id_profesional_externo:
            opcion.id_profesional_externo
              ? Number(
                  opcion.id_profesional_externo
                )
              : null

        })
      );


    // ==================================================
    // CONSERVAR SOLO LOS QUE SIGUEN EXISTIENDO
    // EN EL CATÁLOGO AUTORIZADO ACTUAL
    // ==================================================

    const opcionesValidas =
      opcionesAnteriores.filter(
        opcion => {

          return profesionales.some(
            profesional => {

              // ========================================
              // MIRRORSOUL
              // ========================================

              if (
                opcion.tipo_profesional ===
                "mirrorsoul"
              ) {

                return (

                  profesional
                    .tipo_profesional ===
                    "mirrorsoul" &&


                  Number(
                    profesional.id_psicologo
                  ) ===
                  Number(
                    opcion.id_psicologo
                  )

                );

              }


              // ========================================
              // EXTERNO
              // ========================================

              if (
                opcion.tipo_profesional ===
                "externo"
              ) {

                return (

                  profesional
                    .tipo_profesional ===
                    "externo" &&


                  Number(
                    profesional
                      .id_profesional_externo
                  ) ===
                  Number(
                    opcion
                      .id_profesional_externo
                  )

                );

              }


              return false;

            }
          );

        }
      );


    // ==================================================
    // ACTUALIZAR SELECCIÓN REAL
    // ==================================================

    setSeleccionProfesionales(
      opcionesValidas
    );


  },
  [
    detalle?.opciones,
    profesionales
  ]
);
  // ==================================================
  // CREAR CANALIZACIÓN MANUAL DESDE RH
  // ==================================================

  const crearCanalizacion =
    async e => {
      e.preventDefault();

      if (
        !nueva.motivo.trim()
      ) {
        setError(
          "Debes escribir el motivo de la canalización."
        );

        return;
      }

      try {
        setProcesando(true);
        setError("");
        setMensaje("");

        const payload = {
          origen:
            nueva.origen,

          motivo:
            nueva.motivo.trim()
        };

        if (
          String(
            nueva.id_referencia_origen
          ).trim()
        ) {
          payload.id_referencia_origen =
            Number(
              nueva.id_referencia_origen
            );
        }

        const { data } =
          await axios.post(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones`,
            payload,
            config
          );

        setMensaje(
          data?.message ||
          "Canalización creada correctamente."
        );

        setNueva({
          origen:
            "observacion_rh",

          id_referencia_origen:
            "",

          motivo:
            ""
        });

        setMostrarNueva(
          false
        );

        await cargarCanalizaciones();

        if (
          data?.canalizacion
            ?.id_canalizacion
        ) {
          await cargarDetalle(
            data
              .canalizacion
              .id_canalizacion
          );
        }

      } catch (err) {
        console.error(
          "❌ Error creando canalización:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible crear la canalización."
        );

      } finally {
        setProcesando(
          false
        );
      }
    };

  // ==================================================
  // RH DECIDE SOBRE RECOMENDACIÓN DEL SISTEMA
  // ==================================================

  const decidirRecomendacion =
    async (
      recomendacion,
      decision
    ) => {
      const idRecomendacion =
        recomendacion
          .id_recomendacion;

      const observacion =
        String(
          observacionesRecomendacion[
            idRecomendacion
          ] || ""
        ).trim();

      if (
        [
          "seguimiento",
          "no_canalizar"
        ].includes(
          decision
        ) &&
        !observacion
      ) {
        setError(
          "Escribe una observación para justificar la decisión de RH."
        );

        return;
      }

      const texto =
        decision ===
        "canalizar"
          ? "¿Confirmas que RH autoriza crear la canalización?"
          : decision ===
            "seguimiento"
          ? "¿Confirmas que RH dará seguimiento sin canalizar por ahora?"
          : "¿Confirmas que RH determina no canalizar?";

      if (
        !window.confirm(
          texto
        )
      ) {
        return;
      }

      try {
        setProcesando(
          true
        );

        setError("");
        setMensaje("");

        const { data } =
          await axios.put(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/recomendaciones/${idRecomendacion}/decision`,
            {
              decision_rh:
                decision,

              observacion_rh:
                observacion ||
                null
            },
            config
          );

        setMensaje(
          data?.message ||
          "Decisión registrada correctamente."
        );

        setObservacionesRecomendacion(
          prev => ({
            ...prev,
            [idRecomendacion]:
              ""
          })
        );

        await cargarRecomendaciones();

        if (
          decision ===
            "canalizar" &&

          data?.canalizacion
            ?.id_canalizacion
        ) {
          await cargarCanalizaciones();

          await cargarDetalle(
            data
              .canalizacion
              .id_canalizacion
          );
        }

      } catch (err) {
        console.error(
          "❌ Error registrando decisión RH:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible registrar la decisión de RH."
        );

      } finally {
        setProcesando(
          false
        );
      }
    };

  // ==================================================
  // PROFESIONALES
  // ==================================================

  const estaSeleccionado =
    profesional => {
      return seleccionProfesionales.some(
        item => {
          if (
            profesional
              .tipo_profesional ===
            "mirrorsoul"
          ) {
            return (
              item.tipo_profesional ===
                "mirrorsoul" &&

              Number(
                item.id_psicologo
              ) ===
                Number(
                  profesional
                    .id_psicologo
                )
            );
          }

          return (
            item.tipo_profesional ===
              "externo" &&

            Number(
              item
                .id_profesional_externo
            ) ===
              Number(
                profesional
                  .id_profesional_externo
              )
          );
        }
      );
    };

  const alternarProfesional =
    profesional => {
      const existe =
        estaSeleccionado(
          profesional
        );

      if (existe) {
        setSeleccionProfesionales(
          prev =>
            prev.filter(
              item => {
                if (
                  profesional
                    .tipo_profesional ===
                  "mirrorsoul"
                ) {
                  return !(
                    item.tipo_profesional ===
                      "mirrorsoul" &&

                    Number(
                      item.id_psicologo
                    ) ===
                      Number(
                        profesional
                          .id_psicologo
                      )
                  );
                }

                return !(
                  item.tipo_profesional ===
                    "externo" &&

                  Number(
                    item
                      .id_profesional_externo
                  ) ===
                    Number(
                      profesional
                        .id_profesional_externo
                    )
                );
              }
            )
        );

        return;
      }

      if (
        seleccionProfesionales.length >=
        5
      ) {
        setError(
          "Puedes enviar máximo 5 opciones."
        );

        return;
      }

      setError("");

      setSeleccionProfesionales(
        prev => [
          ...prev,
          {
            tipo_profesional:
              profesional
                .tipo_profesional,

            id_psicologo:
              profesional
                .tipo_profesional ===
              "mirrorsoul"
                ? Number(
                    profesional
                      .id_psicologo
                  )
                : null,

            id_profesional_externo:
              profesional
                .tipo_profesional ===
              "externo"
                ? Number(
                    profesional
                      .id_profesional_externo
                  )
                : null
          }
        ]
      );
    };

  const abrirOpcionesProfesionales =
    () => {
      setAbiertas(
        prev => ({
          ...prev,
          profesionales: true
        })
      );

      setTimeout(
        () => {
          opcionesRef.current
            ?.scrollIntoView({
              behavior: "smooth",
              block: "start"
            });
        },
        80
      );
    };

  const alternarAreaRanking =
    idArea => {
      const id =
        Number(
          idArea
        );

      setCriteriosRanking(
        prev => {
          const seleccionadas =
            Array.isArray(
              prev
                .areas_atencion_requeridas
            )
              ? prev
                  .areas_atencion_requeridas
              : [];

          const existe =
            seleccionadas.includes(
              id
            );

          return {
            ...prev,

            areas_atencion_requeridas:
              existe
                ? seleccionadas.filter(
                    item =>
                      Number(item) !==
                      id
                  )
                : [
                    ...seleccionadas,
                    id
                  ]
          };
        }
      );

      setRankingActivo(false);
      setProfesionales([]);
      setSeleccionProfesionales([]);
    };


  const guardarCriteriosRanking =
    async () => {
      if (!seleccionadaId) {
        return;
      }

      if (
        !criteriosRanking
          .modalidad_atencion_preferida
      ) {
        setError(
          "Selecciona la modalidad de atención."
        );

        return;
      }

      if (
        !criteriosRanking
          .areas_atencion_requeridas
          .length
      ) {
        setError(
          esCanalizacionSistema
            ? "Esta canalización del sistema no tiene áreas de atención determinadas. Revisa la detección que originó la canalización."
            : "Selecciona al menos un área de atención."
        );

        return;
      }

      try {
        setProcesando(true);
        setError("");
        setMensaje("");

        const { data } =
          await axios.put(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/${seleccionadaId}/criterios-ranking`,
            {
              modalidad_atencion_preferida:
                criteriosRanking
                  .modalidad_atencion_preferida,

              areas_atencion_requeridas:
                criteriosRanking
                  .areas_atencion_requeridas
            },
            config
          );

        setMensaje(
          data?.message ||
          "Criterios guardados correctamente."
        );

        await cargarDetalle(
          seleccionadaId
        );

      } catch (err) {
        console.error(
          "❌ Error guardando criterios del ranking:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible guardar los criterios del ranking."
        );

      } finally {
        setProcesando(false);
      }
    };


  const enviarOpciones =
    async () => {
      if (!seleccionadaId) {
        return;
      }

      if (
        !seleccionProfesionales.length
      ) {
        setError(
          "Selecciona al menos un profesional."
        );

        return;
      }

      const confirmar =
        window.confirm(
          `¿Enviar ${seleccionProfesionales.length} opción(es) al empleado?`
        );

      if (!confirmar) {
        return;
      }

      try {
        setProcesando(
          true
        );

        setError("");
        setMensaje("");
        setEnlaceEmpleado("");

        const tokenPublico =
          detalle
            ?.canalizacion
            ?.token_publico ||
          canalizacionSeleccionada
            ?.token_publico;

        const { data } =
          await axios.post(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/${seleccionadaId}/opciones`,
            {
              opciones:
                seleccionProfesionales
            },
            config
          );

        let enlace = "";

        if (tokenPublico) {
          enlace =
            `${window.location.origin}/canalizacion/${tokenPublico}`;

          setEnlaceEmpleado(
            enlace
          );

          try {
            await navigator.clipboard.writeText(
              enlace
            );

            setMensaje(
              `${data?.message || "Opciones enviadas correctamente."} El enlace del empleado también se copió al portapapeles.`
            );

          } catch {
            setMensaje(
              `${data?.message || "Opciones enviadas correctamente."} El enlace ya está disponible abajo para copiarlo.`
            );
          }

        } else {
          setMensaje(
            data?.message ||
            "Opciones enviadas correctamente."
          );

          setError(
            "Las opciones se guardaron, pero no se encontró el token público de esta canalización para generar el enlace."
          );
        }

        await cargarCanalizaciones();

        await cargarDetalle(
          seleccionadaId
        );

        if (enlace) {
          setTimeout(
            () => {
              enlaceRef.current
                ?.scrollIntoView({
                  behavior: "smooth",
                  block: "center"
                });
            },
            150
          );
        }

      } catch (err) {
        console.error(
          "❌ Error enviando opciones:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible enviar las opciones."
        );

      } finally {
        setProcesando(
          false
        );
      }
    };

  // ==================================================
  // SEGUIMIENTO
  // ==================================================

  const guardarSeguimiento =
    async e => {
      e.preventDefault();

      if (!seleccionadaId) {
        return;
      }

      if (
        !seguimiento
          .observacion
          .trim() &&

        !seguimiento
          .motivo_no_seleccion
      ) {
        setError(
          "Registra una observación o el motivo de no selección."
        );

        return;
      }

      try {
        setProcesando(
          true
        );

        setError("");
        setMensaje("");

        const { data } =
          await axios.post(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/${seleccionadaId}/seguimientos`,
            {
              tipo_seguimiento:
                seguimiento
                  .tipo_seguimiento,

              motivo_no_seleccion:
                seguimiento
                  .motivo_no_seleccion ||
                null,

              observacion:
                seguimiento
                  .observacion
                  .trim() ||
                null
            },
            config
          );

        setMensaje(
          data?.message ||
          "Seguimiento guardado."
        );

        setSeguimiento({
          tipo_seguimiento:
            "contacto",

          motivo_no_seleccion:
            "",

          observacion:
            ""
        });

        await cargarCanalizaciones();

        await cargarDetalle(
          seleccionadaId
        );

      } catch (err) {
        console.error(
          "❌ Error guardando seguimiento:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible registrar el seguimiento."
        );

      } finally {
        setProcesando(
          false
        );
      }
    };

  // ==================================================
  // CERRAR
  // ==================================================

  const cerrarCanalizacion =
    async () => {
      if (!seleccionadaId) {
        return;
      }

      const confirmar =
        window.confirm(
          "¿Deseas cerrar administrativamente esta canalización?"
        );

      if (!confirmar) {
        return;
      }

      try {
        setProcesando(
          true
        );

        setError("");
        setMensaje("");

        const { data } =
          await axios.put(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/${seleccionadaId}/cerrar`,
            {
              observacion:
                cierreObservacion
                  .trim() ||
                null
            },
            config
          );

        setMensaje(
          data?.message ||
          "Canalización cerrada."
        );

        setCierreObservacion(
          ""
        );

        await cargarCanalizaciones();

        await cargarDetalle(
          seleccionadaId
        );

      } catch (err) {
        console.error(
          "❌ Error cerrando canalización:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible cerrar la canalización."
        );

      } finally {
        setProcesando(
          false
        );
      }
    };

  // ==================================================
  // CANCELAR
  // ==================================================

  const cancelarCanalizacion =
    async () => {
      if (!seleccionadaId) {
        return;
      }

      if (
        !motivoCancelacion.trim()
      ) {
        setError(
          "Escribe el motivo de cancelación."
        );

        return;
      }

      const confirmar =
        window.confirm(
          "¿Seguro que deseas cancelar esta canalización?"
        );

      if (!confirmar) {
        return;
      }

      try {
        setProcesando(
          true
        );

        setError("");
        setMensaje("");

        const { data } =
          await axios.put(
            `${API_URL}/api/empleados/${idEmpleado}/canalizaciones/${seleccionadaId}/cancelar`,
            {
              motivo:
                motivoCancelacion
                  .trim()
            },
            config
          );

        setMensaje(
          data?.message ||
          "Canalización cancelada."
        );

        setMotivoCancelacion(
          ""
        );

        await cargarCanalizaciones();

        await cargarDetalle(
          seleccionadaId
        );

      } catch (err) {
        console.error(
          "❌ Error cancelando canalización:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible cancelar la canalización."
        );

      } finally {
        setProcesando(
          false
        );
      }
    };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.loading}>
          Cargando canalización...
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* ============================================
            REGRESAR AL EXPEDIENTE
        ============================================ */}

        <button
          type="button"
          style={styles.backButton}
          onClick={() =>
            navigate(
              `/empleado/${idEmpleado}`
            )
          }
        >
          ← Regresar al expediente
        </button>

        {/* ============================================
            CABECERA
        ============================================ */}

        <div style={styles.topRow}>
          <div>
            <h1 style={styles.title}>
              Canalización
            </h1>

            <p style={styles.subtitle}>
              Detección, revisión y seguimiento administrativo de apoyo profesional
            </p>
          </div>

          <button
            type="button"
            style={styles.primaryButton}
            onClick={() =>
              setMostrarNueva(
                prev =>
                  !prev
              )
            }
          >
            {mostrarNueva
              ? "Cerrar formulario"
              : "+ Canalización detectada por RH"}
          </button>
        </div>

        {empleado && (
          <div style={styles.employeeCard}>
            <div>
              <strong style={styles.employeeName}>
                {empleado.nombre}
              </strong>

              <div style={styles.employeeMeta}>
                {empleado.id_mirror ||
                  "Sin ID Mirror"}

                {" · "}

                {empleado.puesto ||
                  "Sin puesto"}

                {" · "}

                {empleado.departamento ||
                  "Sin departamento"}
              </div>
            </div>

            <span style={styles.rhBadge}>
              RH
            </span>
          </div>
        )}

        <div style={styles.privacyBox}>
          <strong>
            🔒 Módulo administrativo RH
          </strong>

          <span>
            La canalización utiliza información laboral autorizada.
            No muestra expediente clínico, sesiones, diagnósticos ni notas terapéuticas.
          </span>
        </div>

        {error && (
          <div style={styles.errorBox}>
            {error}
          </div>
        )}

        {mensaje && (
          <div style={styles.successBox}>
            {mensaje}
          </div>
        )}

        {/* ============================================
            RECOMENDACIONES DEL SISTEMA
        ============================================ */}

        <Seccion
          titulo="🤖 Recomendaciones del sistema"
          subtitulo={
            recomendacionesPendientes.length
              ? `${recomendacionesPendientes.length} pendiente(s) de revisión por RH`
              : "Sin recomendaciones pendientes"
          }
          abierta={
            abiertas.recomendaciones
          }
          alerta={
            recomendacionesPendientes.length >
            0
          }
          onToggle={() =>
            setAbiertas(
              prev => ({
                ...prev,

                recomendaciones:
                  !prev.recomendaciones
              })
            )
          }
        >
          <div style={styles.systemIntro}>
            <div style={styles.systemIcon}>
              ✨
            </div>

            <div>
              <strong>
                Detección asistida por el sistema
              </strong>

              <p>
                NOM-035 y las evaluaciones RH conectadas pueden generar recomendaciones para revisión. Abre únicamente la prueba que quieras revisar; RH conserva siempre la decisión final.
              </p>
            </div>
          </div>

          {cargandoRecomendaciones ? (
            <div style={styles.empty}>
              Cargando recomendaciones...
            </div>

          ) : !recomendaciones.length ? (
            <div style={styles.noRecommendations}>
              <strong>
                Aún no hay recomendaciones automáticas
              </strong>

              <span>
                Cuando NOM-035, GAD-7 o WHO-5 generen un resultado que deba revisarse, aparecerá aquí automáticamente.
              </span>

              <span style={styles.futureInfo}>
                La pre-evaluación IA se muestra desde el resultado original de la prueba; Canalización no genera una segunda IA.
              </span>
            </div>

          ) : (
            <div style={styles.recommendationsList}>
              {recomendaciones.map(
                item => {
                  const pendiente =
                    item.decision_rh ===
                    "pendiente";

                  const abierta =
                    Number(
                      recomendacionAbiertaId
                    ) ===
                    Number(
                      item.id_recomendacion
                    );

                  const factores =
                    parseFactores(
                      item.factores_detectados
                    );

                  const factoresObjeto =
                    Object.fromEntries(
                      factores
                        .filter(
                          factor =>
                            factor &&
                            typeof factor ===
                              "object" &&
                            factor.clave
                        )
                        .map(
                          factor => [
                            factor.clave,
                            factor.dato
                          ]
                        )
                    );

                  const esPruebaRH =
                    item.origen ===
                    "otra_prueba";

                  const tituloPrueba =
                    item.origen ===
                    "nom035"
                      ? `NOM-035 · Guía ${item.guia || ""}`
                      : esPruebaRH
                      ? (
                          item.prueba_nombre ||
                          factoresObjeto.prueba ||
                          item.prueba_version ||
                          "Evaluación RH"
                        )
                      : nombreOrigen(
                          item.origen
                        );

                  const subtituloPrueba =
                    item.origen ===
                    "nom035"
                      ? item.cuestionario_nombre
                      : esPruebaRH
                      ? (
                          item.prueba_version ||
                          item.prueba_categoria ||
                          "Prueba laboral"
                        )
                      : null;

                  return (
                    <div
                      key={
                        item.id_recomendacion
                      }
                      style={{
                        ...styles.recommendationCard,

                        ...(pendiente
                          ? styles.recommendationPending
                          : {})
                      }}
                    >
                      <button
                        type="button"
                        style={
                          styles.recommendationToggle
                        }
                        onClick={() =>
                          alternarRecomendacion(
                            item.id_recomendacion
                          )
                        }
                      >
                        <div
                          style={
                            styles.recommendationSummary
                          }
                        >
                          <div>
                            <div style={styles.badgeRow}>
                              <span style={styles.systemBadge}>
                                🤖 Sistema
                              </span>

                              <span
                                style={
                                  item.nivel_recomendacion ===
                                  "canalizacion"
                                    ? styles.dangerBadge

                                    : item.nivel_recomendacion ===
                                      "seguimiento"

                                    ? styles.warningBadge

                                    : styles.okBadge
                                }
                              >
                                {
                                  etiquetasRecomendacion[
                                    item.nivel_recomendacion
                                  ] ||
                                  item.nivel_recomendacion
                                }
                              </span>

                              <span
                                style={
                                  pendiente
                                    ? styles.pendingMiniBadge
                                    : styles.reviewedMiniBadge
                                }
                              >
                                {pendiente
                                  ? "Pendiente RH"
                                  : "Revisada"}
                              </span>
                            </div>

                            <h3
                              style={
                                styles.recommendationTitleCompact
                              }
                            >
                              {tituloPrueba}
                            </h3>

                            {subtituloPrueba && (
                              <span
                                style={
                                  styles.testNameCompact
                                }
                              >
                                {subtituloPrueba}
                              </span>
                            )}
                          </div>

                          <div
                            style={
                              styles.recommendationSummaryRight
                            }
                          >
                            {esPruebaRH &&
                              item.prueba_puntaje_total !==
                                null &&
                              item.prueba_puntaje_total !==
                                undefined && (
                                <span
                                  style={
                                    styles.scoreBadge
                                  }
                                >
                                  Puntaje{" "}
                                  {
                                    item.prueba_puntaje_total
                                  }
                                </span>
                              )}

                            <span
                              style={
                                styles.compactDate
                              }
                            >
                              {formatearFecha(
                                item.fecha_deteccion
                              )}
                            </span>

                            <span
                              style={
                                styles.openIndicator
                              }
                            >
                              {abierta
                                ? "▲"
                                : "▼"}
                            </span>
                          </div>
                        </div>
                      </button>

                      {abierta && (
                        <div
                          style={
                            styles.recommendationBody
                          }
                        >
                          <div
                            style={
                              styles.compactMetaGrid
                            }
                          >
                            <div>
                              <span
                                style={
                                  styles.dataLabel
                                }
                              >
                                Decisión RH
                              </span>

                              <strong>
                                {
                                  etiquetasDecision[
                                    item.decision_rh
                                  ] ||
                                  item.decision_rh
                                }
                              </strong>
                            </div>

                            <div>
                              <span
                                style={
                                  styles.dataLabel
                                }
                              >
                                Referencia
                              </span>

                              <strong>
                                #
                                {
                                  item.id_referencia_origen
                                }
                              </strong>
                            </div>

                            {esPruebaRH && (
                              <div>
                                <span
                                  style={
                                    styles.dataLabel
                                  }
                                >
                                  Categoría
                                </span>

                                <strong>
                                  {item.prueba_categoria ||
                                    factoresObjeto.categoria ||
                                    "—"}
                                </strong>
                              </div>
                            )}
                          </div>

                          {esPruebaRH && (
                            <div
                              style={
                                styles.rhTestResultBox
                              }
                            >
                              <div
                                style={
                                  styles.rhTestResultHeader
                                }
                              >
                                <strong>
                                  📊 Resultado de la prueba
                                </strong>

                                {item.prueba_version && (
                                  <span
                                    style={
                                      styles.versionBadge
                                    }
                                  >
                                    {
                                      item.prueba_version
                                    }
                                  </span>
                                )}
                              </div>

                              {item.prueba_resultado_texto && (
                                <p
                                  style={
                                    styles.compactParagraph
                                  }
                                >
                                  <b>Resultado:</b>{" "}
                                  {
                                    item.prueba_resultado_texto
                                  }
                                </p>
                              )}

                              {item.prueba_interpretacion && (
                                <p
                                  style={
                                    styles.compactParagraph
                                  }
                                >
                                  <b>Interpretación:</b>{" "}
                                  {
                                    item.prueba_interpretacion
                                  }
                                </p>
                              )}

                              {item.prueba_interpretacion_laboral && (
                                <p
                                  style={
                                    styles.compactParagraph
                                  }
                                >
                                  <b>
                                    Interpretación laboral:
                                  </b>{" "}
                                  {
                                    item.prueba_interpretacion_laboral
                                  }
                                </p>
                              )}
                            </div>
                          )}

                          {!esPruebaRH &&
                            item.resultado_detectado && (
                              <div
                                style={
                                  styles.detectedResult
                                }
                              >
                                <span
                                  style={
                                    styles.dataLabel
                                  }
                                >
                                  Resultado detectado
                                </span>

                                <p
                                  style={
                                    styles.compactParagraph
                                  }
                                >
                                  {
                                    item.resultado_detectado
                                  }
                                </p>
                              </div>
                            )}

                          {item.origen ===
                            "nom035" && (
                            <div
                              style={
                                styles.nomResultBox
                              }
                            >
                              <div
                                style={
                                  styles.nomResultHeader
                                }
                              >
                                <strong>
                                  📋 Resultado NOM-035
                                </strong>

                                {Number(
                                  item.nom_requiere_accion
                                ) === 1 && (
                                  <span
                                    style={
                                      styles.dangerBadge
                                    }
                                  >
                                    ⚠ Valoración requerida
                                  </span>
                                )}
                              </div>

                              <p
                                style={
                                  styles.nomResultText
                                }
                              >
                                {item.nom_resultado_general ||
                                  item.resultado_detectado ||
                                  "Sin resultado registrado."}
                              </p>

                              {item.nom_recomendaciones && (
                                <div
                                  style={
                                    styles.nomRecommendation
                                  }
                                >
                                  <strong>
                                    Recomendación:
                                  </strong>

                                  <span>
                                    {
                                      item.nom_recomendaciones
                                    }
                                  </span>
                                </div>
                              )}
                            </div>
                          )}

                          <div style={styles.aiBoxCompact}>
                            <div style={styles.aiHeader}>
                              <strong>
                                🤖 Pre-evaluación IA
                              </strong>

                              <span style={styles.aiLabel}>
                                Orientativa
                              </span>
                            </div>

                            {item.preevaluacion_ia ? (
                              <p style={styles.aiTextCompact}>
                                {item.preevaluacion_ia}
                              </p>
                            ) : (
                              <p style={styles.aiEmpty}>
                                Esta recomendación todavía no cuenta con preevaluación IA.
                              </p>
                            )}

                            <small style={styles.aiNotice}>
                              Apoyo para RH; no constituye diagnóstico clínico.
                            </small>
                          </div>

                          {pendiente ? (
                            <div
                              style={
                                styles.decisionBoxCompact
                              }
                            >
                              <label
                                style={
                                  styles.labelCompact
                                }
                              >
                                Observación de RH

                                <textarea
                                  style={
                                    styles.smallTextarea
                                  }
                                  value={
                                    observacionesRecomendacion[
                                      item.id_recomendacion
                                    ] || ""
                                  }
                                  onChange={e =>
                                    setObservacionesRecomendacion(
                                      prev => ({
                                        ...prev,

                                        [item.id_recomendacion]:
                                          e.target.value
                                      })
                                    )
                                  }
                                  placeholder="Observación para respaldar la decisión de RH..."
                                />
                              </label>

                              <div
                                style={
                                  styles.decisionButtons
                                }
                              >
                                <button
                                  type="button"
                                  style={
                                    styles.approveButton
                                  }
                                  disabled={
                                    procesando
                                  }
                                  onClick={() =>
                                    decidirRecomendacion(
                                      item,
                                      "canalizar"
                                    )
                                  }
                                >
                                  ✓ Canalizar
                                </button>

                                <button
                                  type="button"
                                  style={
                                    styles.followButton
                                  }
                                  disabled={
                                    procesando
                                  }
                                  onClick={() =>
                                    decidirRecomendacion(
                                      item,
                                      "seguimiento"
                                    )
                                  }
                                >
                                  ◷ Seguimiento
                                </button>

                                <button
                                  type="button"
                                  style={
                                    styles.noButton
                                  }
                                  disabled={
                                    procesando
                                  }
                                  onClick={() =>
                                    decidirRecomendacion(
                                      item,
                                      "no_canalizar"
                                    )
                                  }
                                >
                                  No canalizar
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div
                              style={
                                styles.reviewedBox
                              }
                            >
                              <strong>
                                Decisión registrada:{" "}
                                {
                                  etiquetasDecision[
                                    item.decision_rh
                                  ] ||
                                  item.decision_rh
                                }
                              </strong>

                              {item.observacion_rh && (
                                <div
                                  style={
                                    styles.rhDecisionReason
                                  }
                                >
                                  <span
                                    style={
                                      styles.dataLabel
                                    }
                                  >
                                    {item.decision_rh ===
                                    "no_canalizar"
                                      ? "Motivo de RH para no canalizar"
                                      : item.decision_rh ===
                                        "seguimiento"
                                      ? "Motivo de RH para dar seguimiento"
                                      : "Observación de RH"}
                                  </span>

                                  <p
                                    style={
                                      styles.compactParagraph
                                    }
                                  >
                                    {
                                      item.observacion_rh
                                    }
                                  </p>
                                </div>
                              )}

                              {item.id_canalizacion && (
                                <span>
                                  Canalización creada:{" "}
                                  <strong>
                                    #
                                    {
                                      item.id_canalizacion
                                    }
                                  </strong>
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                }
              )}
            </div>
          )}
        </Seccion>
                {/* ============================================
            NUEVA CANALIZACIÓN MANUAL
        ============================================ */}

        {mostrarNueva && (
          <form
            style={styles.newCard}
            onSubmit={crearCanalizacion}
          >
            <div style={styles.manualHeader}>
              <div>
                <h3 style={styles.cardTitle}>
                  Nueva canalización
                </h3>

                <p style={styles.manualDescription}>
                  Esta canalización nace por observación o valoración directa de RH.
                </p>
              </div>

              <span style={styles.rhDetectedBadge}>
                👤 Detectado por RH
              </span>
            </div>

            <div style={styles.detectTypeBox}>
              <span style={styles.dataLabel}>
                Origen de detección
              </span>

              <strong>
                Detectado por RH
              </strong>

              <small>
                “Sistema” no puede seleccionarse manualmente.
                Una recomendación del sistema solo aparecerá
                cuando provenga de una evaluación real.
              </small>
            </div>

            <div style={styles.formGrid}>
              <label style={styles.label}>
                ¿Dónde lo detectó RH?

                <select
                  style={styles.input}
                  value={nueva.origen}
                  onChange={e =>
                    setNueva(prev => ({
                      ...prev,
                      origen: e.target.value
                    }))
                  }
                >
                  {ORIGENES_MANUALES.map(
                    item => (
                      <option
                        key={item.value}
                        value={item.value}
                      >
                        {item.label}
                      </option>
                    )
                  )}
                </select>
              </label>

              <label style={styles.label}>
                ID de referencia

                <span style={styles.optional}>
                  Opcional por ahora
                </span>

                <input
                  type="number"
                  min="1"
                  style={styles.input}
                  value={
                    nueva
                      .id_referencia_origen
                  }
                  onChange={e =>
                    setNueva(prev => ({
                      ...prev,

                      id_referencia_origen:
                        e.target.value
                    }))
                  }
                  placeholder="Solo si existe un registro relacionado"
                />
              </label>
            </div>

            <label style={styles.label}>
              ¿Qué observó RH y por qué considera necesaria la canalización?

              <textarea
                style={styles.textarea}
                value={nueva.motivo}
                onChange={e =>
                  setNueva(prev => ({
                    ...prev,
                    motivo:
                      e.target.value
                  }))
                }
                placeholder="Describe los indicadores, situación laboral, entrevista u observación que llevaron a RH a considerar la canalización..."
              />
            </label>

            <div style={styles.actionsRight}>
              <button
                type="submit"
                style={styles.primaryButton}
                disabled={procesando}
              >
                {procesando
                  ? "Creando..."
                  : "Crear canalización"}
              </button>
            </div>
          </form>
        )}

        {/* ============================================
            CANALIZACIONES
        ============================================ */}

        <div style={styles.layout}>

          {/* ==========================================
              SIDEBAR
          ========================================== */}

          <div style={styles.sidebar}>
            <div style={styles.sidebarHeader}>
              <strong>
                Canalizaciones
              </strong>

              <span style={styles.counter}>
                {canalizaciones.length}
              </span>
            </div>

            {!canalizaciones.length ? (
              <div style={styles.empty}>
                Este empleado todavía no tiene canalizaciones.
              </div>
            ) : (
              canalizaciones.map(
                item => {
                  const activa =
                    Number(
                      item.id_canalizacion
                    ) ===
                    Number(
                      seleccionadaId
                    );

                  return (
                    <button
                      key={
                        item.id_canalizacion
                      }
                      type="button"
                      style={{
                        ...styles.canalizacionItem,

                        ...(activa
                          ? styles.canalizacionItemActive
                          : {})
                      }}
                      onClick={() =>
                        cargarDetalle(
                          item.id_canalizacion
                        )
                      }
                    >
                      <div style={styles.itemTop}>
                        <strong>
                          Canalización #
                          {item.id_canalizacion}
                        </strong>

                        {Number(
                          item
                            .seguimiento_requerido
                        ) === 1 && (
                          <span style={styles.alertBadge}>
                            Seguimiento
                          </span>
                        )}
                      </div>

                      <div style={styles.sourceLine}>
                        <span
                          style={
                            item.tipo_deteccion ===
                            "sistema"
                              ? styles.systemMiniBadge
                              : styles.rhMiniBadge
                          }
                        >
                          {item.tipo_deteccion ===
                          "sistema"
                            ? "🤖 Sistema"
                            : "👤 RH"}
                        </span>
                      </div>

                      <span style={styles.itemOrigin}>
                        {nombreOrigen(
                          item.origen
                        )}
                      </span>

                      {item.id_referencia_origen && (
                        <span style={styles.itemReference}>
                          Ref. #
                          {
                            item.id_referencia_origen
                          }
                        </span>
                      )}

                      <span style={styles.itemStatus}>
                        {
                          etiquetasEstado[
                            item.estatus
                          ] ||
                          item.estatus
                        }
                      </span>

                      <span style={styles.itemDate}>
                        {formatearFecha(
                          item.fecha_creacion
                        )}
                      </span>
                    </button>
                  );
                }
              )
            )}
          </div>

          {/* ==========================================
              CONTENIDO
          ========================================== */}

          <div style={styles.content}>

            {!seleccionadaId ? (
              <div style={styles.emptyLarge}>
                <div style={styles.emptyIcon}>
                  🧭
                </div>

                <strong>
                  Selecciona una canalización
                </strong>

                <span>
                  Aquí podrás revisar su origen, profesionales,
                  elección, seguimiento e historial.
                </span>
              </div>

            ) : cargandoDetalle ? (
              <div style={styles.loading}>
                Cargando detalle...
              </div>

            ) : detalle ? (
              <>

                {/* ====================================
                    CABECERA DEL DETALLE
                ==================================== */}

                <div style={styles.detailHeader}>
                  <div>
                    <h2 style={styles.detailTitle}>
                      Canalización #
                      {
                        detalle
                          .canalizacion
                          ?.id_canalizacion
                      }
                    </h2>

                    <div style={styles.detailBadges}>
                      <span style={styles.statusBadge}>
                        {
                          etiquetasEstado[
                            detalle
                              .canalizacion
                              ?.estatus
                          ] ||
                          detalle
                            .canalizacion
                            ?.estatus
                        }
                      </span>

                      <span
                        style={
                          detalle
                            .canalizacion
                            ?.tipo_deteccion ===
                          "sistema"
                            ? styles.systemBadge
                            : styles.rhDetectedBadge
                        }
                      >
                        {detalle
                          .canalizacion
                          ?.tipo_deteccion ===
                        "sistema"
                          ? "🤖 Recomendado por sistema"
                          : "👤 Detectado por RH"}
                      </span>

                      {Number(
                        detalle
                          .canalizacion
                          ?.seguimiento_requerido
                      ) === 1 && (
                        <span style={styles.alertBadgeLarge}>
                          ⚠ Seguimiento requerido
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* ====================================
                    ALERTA 5 DÍAS
                ==================================== */}

                {Number(
                  detalle
                    .canalizacion
                    ?.seguimiento_requerido
                ) === 1 && (
                  <div style={styles.followAlert}>
                    <strong>
                      ⚠ Han transcurrido 5 días sin selección
                    </strong>

                    <span>
                      RH debe contactar al empleado y dejar evidencia del seguimiento.
                    </span>
                  </div>
                )}

                {/* ====================================
                    ORIGEN Y MOTIVO
                ==================================== */}

                <Seccion
                  titulo="Origen y motivo"
                  subtitulo={
                    detalle
                      .canalizacion
                      ?.tipo_deteccion ===
                    "sistema"
                      ? "Recomendación generada por el sistema y revisada por RH"
                      : "Detección realizada directamente por RH"
                  }
                  abierta={
                    abiertas.origen
                  }
                  onToggle={() =>
                    setAbiertas(
                      prev => ({
                        ...prev,
                        origen:
                          !prev.origen
                      })
                    )
                  }
                >
                  <div style={styles.dataGrid}>
                    <div style={styles.dataItem}>
                      <span style={styles.dataLabel}>
                        Origen de detección
                      </span>

                      <strong>
                        {detalle
                          .canalizacion
                          ?.tipo_deteccion ===
                        "sistema"
                          ? "Recomendado por el sistema"
                          : "Detectado por RH"}
                      </strong>
                    </div>

                    <div style={styles.dataItem}>
                      <span style={styles.dataLabel}>
                        Fuente
                      </span>

                      <strong>
                        {nombreOrigen(
                          detalle
                            .canalizacion
                            ?.origen
                        )}
                      </strong>
                    </div>

                    <div style={styles.dataItem}>
                      <span style={styles.dataLabel}>
                        ID de referencia
                      </span>

                      <strong>
                        {detalle
                          .canalizacion
                          ?.id_referencia_origen
                          ? `#${detalle.canalizacion.id_referencia_origen}`
                          : "Sin referencia"}
                      </strong>
                    </div>

                    <div style={styles.dataItem}>
                      <span style={styles.dataLabel}>
                        Fecha de creación
                      </span>

                      <strong>
                        {formatearFecha(
                          detalle
                            .canalizacion
                            ?.fecha_creacion
                        )}
                      </strong>
                    </div>
                  </div>

                  {detalle
                    .canalizacion
                    ?.tipo_deteccion ===
                    "sistema" && (
                    <>
                      <div style={styles.systemDetailBox}>
                        <div>
                          <span style={styles.dataLabel}>
                            Recomendación del sistema
                          </span>

                          <strong>
                            {
                              etiquetasRecomendacion[
                                detalle
                                  .canalizacion
                                  ?.recomendacion_sistema
                              ] ||
                              detalle
                                .canalizacion
                                ?.recomendacion_sistema ||
                              "Sin información"
                            }
                          </strong>
                        </div>

                        <div>
                          <span style={styles.dataLabel}>
                            Decisión RH
                          </span>

                          <strong>
                            {
                              etiquetasDecision[
                                detalle
                                  .canalizacion
                                  ?.decision_rh
                              ] ||
                              detalle
                                .canalizacion
                                ?.decision_rh
                            }
                          </strong>
                        </div>
                      </div>

                      <div style={styles.aiBox}>
                        <div style={styles.aiHeader}>
                          <strong>
                            🤖 Pre-evaluación IA
                          </strong>

                          <span style={styles.aiLabel}>
                            Orientativa
                          </span>
                        </div>

                        {detalle
                          .canalizacion
                          ?.preevaluacion_ia ? (
                          <p style={styles.aiText}>
                            {
                              detalle
                                .canalizacion
                                .preevaluacion_ia
                            }
                          </p>
                        ) : (
                          <p style={styles.aiEmpty}>
                            Sin preevaluación IA registrada.
                          </p>
                        )}

                        <small style={styles.aiNotice}>
                          Herramienta de apoyo para RH. No constituye diagnóstico clínico.
                        </small>
                      </div>
                    </>
                  )}

                  <div style={styles.reasonBox}>
                    <span style={styles.dataLabel}>
                      Motivo de canalización
                    </span>

                    <p>
                      {
                        detalle
                          .canalizacion
                          ?.motivo
                      }
                    </p>
                  </div>

                  {detalle
                    .canalizacion
                    ?.motivo_decision_rh && (
                    <div style={styles.reasonBox}>
                      <span style={styles.dataLabel}>
                        Observación / decisión de RH
                      </span>

                      <p>
                        {
                          detalle
                            .canalizacion
                            .motivo_decision_rh
                        }
                      </p>
                    </div>
                  )}

                  {!!detalle.opciones?.some(
                    opcion =>
                      [
                        "rechazado",
                        "rechazada"
                      ].includes(
                        String(
                          opcion
                            .estado_respuesta_profesional ||
                          ""
                        )
                          .trim()
                          .toLowerCase()
                      )
                  ) && (
                    <div style={styles.rejectedHistoryBox}>
                      <strong style={styles.rejectedHistoryTitle}>
                        Profesionales que rechazaron esta canalización
                      </strong>

                      <span style={styles.rejectedHistoryHelp}>
                        No volverán a aparecer en el ranking de esta canalización.
                      </span>

                      {detalle.opciones
                        .filter(
                          opcion =>
                            [
                              "rechazado",
                              "rechazada"
                            ].includes(
                              String(
                                opcion
                                  .estado_respuesta_profesional ||
                                ""
                              )
                                .trim()
                                .toLowerCase()
                            )
                        )
                        .map(
                          opcion => {
                            const profesional =
                              enriquecerOpcion(
                                opcion
                              );

                            return (
                              <div
                                key={`rechazo-${opcion.id_opcion}`}
                                style={styles.rejectedProfessionalRow}
                              >
                                <div>
                                  <strong>
                                    {profesional.nombre}
                                  </strong>

                                  <div style={styles.rejectedReason}>
                                    <b>
                                      Motivo:
                                    </b>{" "}
                                    {opcion
                                      .motivo_rechazo_profesional ||
                                      "No se registró un motivo."}
                                  </div>

                                  {opcion
                                    .observacion_respuesta_profesional && (
                                    <div style={styles.rejectedObservation}>
                                      {
                                        opcion
                                          .observacion_respuesta_profesional
                                      }
                                    </div>
                                  )}

                                  {opcion
                                    .fecha_respuesta_profesional && (
                                    <small>
                                      Respuesta:{" "}
                                      {formatearFecha(
                                        opcion
                                          .fecha_respuesta_profesional
                                      )}
                                    </small>
                                  )}
                                </div>

                                <span style={styles.rejectedBadge}>
                                  Rechazó
                                </span>
                              </div>
                            );
                          }
                        )}
                    </div>
                  )}
                </Seccion>

                {/* ====================================
                    OPCIONES DE PSICÓLOGOS
                ==================================== */}

                <div ref={opcionesRef}>
                <Seccion
                  titulo="Opciones de psicólogos"
                  subtitulo={`${seleccionProfesionales.length}/5 seleccionados`}
                  abierta={
                    abiertas.profesionales
                  }
                  onToggle={() =>
                    setAbiertas(
                      prev => ({
                        ...prev,

                        profesionales:
                          !prev.profesionales
                      })
                    )
                  }
                >
                  {[
                    "seleccion_realizada",
                    "cerrada",
                    "cancelada"
                  ].includes(
                    detalle
                      .canalizacion
                      ?.estatus
                  ) ? (
                    <div style={styles.infoBox}>
                      Las opciones ya no pueden modificarse porque esta canalización está en estado{" "}

                      <strong>
                        {
                          etiquetasEstado[
                            detalle
                              .canalizacion
                              ?.estatus
                          ]
                        }
                      </strong>.
                    </div>

                  ) : (
                    <>
                      <p style={styles.helper}>
                        RH selecciona opciones del catálogo autorizado.
                        RH no crea ni modifica perfiles de psicólogos.
                      </p>

                      <div style={styles.rankingCriteriaBox}>
                        <div style={styles.rankingCriteriaHeader}>
                          <div>
                            <strong>
                              🎯 Criterios para recomendar profesionales
                            </strong>

                            <p style={styles.helper}>
                              Define cómo desea recibir atención el empleado y las áreas que requiere esta canalización.
                            </p>
                          </div>

                          {rankingActivo && (
                            <span style={styles.rankingActiveBadge}>
                              ✓ Ranking actualizado
                            </span>
                          )}
                        </div>

                        <label style={styles.label}>
                          Modalidad de atención

                          <select
                            style={styles.input}
                            value={
                              criteriosRanking
                                .modalidad_atencion_preferida
                            }
                            onChange={e => {
                              setCriteriosRanking(
                                prev => ({
                                  ...prev,
                                  modalidad_atencion_preferida:
                                    e.target.value
                                })
                              );

                              setProfesionales([]);
                              setSeleccionProfesionales([]);
                              setRankingActivo(false);
                            }}
                          >
                            <option value="">
                              Selecciona modalidad
                            </option>

                            <option value="presencial">
                              🏢 Presencial
                            </option>

                            <option value="videollamada">
                              💻 Videollamada
                            </option>

                            <option value="indistinta">
                              🔄 Indistinta
                            </option>
                          </select>
                        </label>

                        {esCanalizacionSistema ? (
                          <div style={styles.infoBox}>
                            <strong>
                              🤖 Áreas determinadas por el sistema
                            </strong>

                            <div style={{ marginTop: 6 }}>
                              Las áreas de atención fueron definidas automáticamente
                              por la detección que originó esta canalización.
                              RH no necesita seleccionarlas nuevamente.
                            </div>
                          </div>

                        ) : (
                          <div style={styles.rankingAreasSection}>
                            <strong>
                              Áreas de atención requeridas
                            </strong>

                            <span style={styles.rankingAreasHelp}>
                              Puedes seleccionar una o varias.
                            </span>

                            <div style={styles.rankingAreasGrid}>
                              {catalogoAreas.map(
                                area => {
                                  const seleccionada =
                                    criteriosRanking
                                      .areas_atencion_requeridas
                                      .includes(
                                        Number(
                                          area.id_area
                                        )
                                      );

                                  return (
                                    <button
                                      key={area.id_area}
                                      type="button"
                                      style={{
                                        ...styles.rankingAreaButton,

                                        ...(seleccionada
                                          ? styles.rankingAreaSelected
                                          : {})
                                      }}
                                      onClick={() =>
                                        alternarAreaRanking(
                                          area.id_area
                                        )
                                      }
                                    >
                                      {seleccionada
                                        ? "✓ "
                                        : ""}

                                      {area.nombre}
                                    </button>
                                  );
                                }
                              )}
                            </div>

                            {!catalogoAreas.length && (
                              <div style={styles.empty}>
                                No hay áreas de atención disponibles.
                              </div>
                            )}
                          </div>
                        )}

                        <div style={styles.actionsRight}>
                          <button
                            type="button"
                            style={{
                              ...styles.primaryButton,

                              ...(procesando
                                ? styles.buttonDisabled
                                : {})
                            }}
                            disabled={procesando}
                            onClick={
                              guardarCriteriosRanking
                            }
                          >
                            {procesando
                              ? "Calculando..."
                              : rankingActivo
                              ? "Actualizar ranking"
                              : "Calcular mejores opciones"}
                          </button>
                        </div>
                      </div>

                      {cargandoProfesionales ? (
                        <div style={styles.empty}>
                          Calculando compatibilidad...
                        </div>

                      ) : !rankingActivo ? (
                        <div style={styles.infoBox}>
                          {esCanalizacionSistema ? (
                            <>
                              Selecciona la modalidad de atención y después presiona{" "}
                              <strong>
                                Calcular mejores opciones
                              </strong>.
                              Las áreas ya fueron determinadas por el sistema.
                            </>
                          ) : (
                            <>
                              Selecciona la modalidad y las áreas de atención, después presiona{" "}
                              <strong>
                                Calcular mejores opciones
                              </strong>.
                            </>
                          )}
                        </div>

                      ) : (
                      <div style={styles.professionalGrid}>
                        {profesionales.map(
                          profesional => {
                            const checked =
                              estaSeleccionado(
                                profesional
                              );

                            const foto =
                              obtenerFotoProfesional(
                                profesional.foto_url
                              );

                            const areasProfesional =
                              Array.isArray(
                                profesional.areas_atencion
                              )
                                ? profesional.areas_atencion
                                : [];

                            const modalidades =
                              [
                                Number(
                                  profesional
                                    .modalidad_presencial
                                ) === 1
                                  ? "🏢 Presencial"
                                  : null,

                                Number(
                                  profesional
                                    .modalidad_videollamada
                                ) === 1
                                  ? "💻 Videollamada"
                                  : null
                              ].filter(Boolean);

                            return (
                              <button
                                key={
                                  profesional
                                    .tipo_profesional ===
                                  "mirrorsoul"
                                    ? `m-${profesional.id_psicologo}`
                                    : `e-${profesional.id_profesional_externo}`
                                }
                                type="button"
                                style={{
                                  ...styles.professionalCard,

                                  ...(checked
                                    ? styles.professionalSelected
                                    : {})
                                }}
                                onClick={() =>
                                  alternarProfesional(
                                    profesional
                                  )
                                }
                              >
                                <div style={styles.professionalTop}>
                                  <div style={styles.avatar}>
                                    {foto ? (
                                      <img
                                        src={foto}
                                        alt={
                                          profesional.nombre ||
                                          "Foto profesional"
                                        }
                                        style={styles.avatarImage}
                                      />
                                    ) : (
                                      String(
                                        profesional.nombre ||
                                        "P"
                                      )
                                        .charAt(0)
                                        .toUpperCase()
                                    )}
                                  </div>

                                  <div style={styles.professionalHeading}>
                                    <strong style={styles.professionalName}>
                                      {profesional.nombre}
                                    </strong>

                                    {profesional
                                      ?.compatibilidad
                                      ?.calculada && (
                                      <div style={styles.rankingScoreRow}>
                                        <span style={styles.rankingScore}>
                                          {
                                            profesional
                                              .compatibilidad
                                              .total
                                          }
                                          /100
                                        </span>

                                        <span style={styles.rankingLevel}>
                                          {
                                            profesional
                                              .compatibilidad
                                              .nivel
                                          }
                                        </span>
                                      </div>
                                    )}

                                    <span style={styles.professionalType}>
                                      {profesional.tipo_profesional ===
                                      "mirrorsoul"
                                        ? "MirrorSoul"
                                        : "Externo"}
                                    </span>

                                    {profesional
                                      .anos_experiencia !==
                                      null &&
                                      profesional
                                        .anos_experiencia !==
                                        undefined && (
                                        <span style={styles.experienceText}>
                                          {profesional.anos_experiencia} año(s) de experiencia
                                        </span>
                                      )}
                                  </div>

                                  <div style={styles.checkboxFake}>
                                    {checked
                                      ? "✓"
                                      : ""}
                                  </div>
                                </div>

                                <div style={styles.professionalBody}>
                                  <span>
                                    <b>
                                      Especialidad:
                                    </b>{" "}

                                    {profesional.especialidad ||
                                      "Pendiente de completar"}
                                  </span>

                                  {!!areasProfesional.length && (
                                    <div style={styles.areasWrap}>
                                      {areasProfesional
                                        .slice(0, 5)
                                        .map(
                                          area => (
                                            <span
                                              key={area}
                                              style={styles.areaChip}
                                            >
                                              {area}
                                            </span>
                                          )
                                        )}

                                      {areasProfesional.length > 5 && (
                                        <span style={styles.moreAreas}>
                                          +{areasProfesional.length - 5}
                                        </span>
                                      )}
                                    </div>
                                  )}

                                  {profesional.descripcion && (
                                    <p style={styles.professionalDescription}>
                                      {profesional.descripcion}
                                    </p>
                                  )}

                                  {(profesional.municipio ||
                                    profesional.estado) && (
                                    <span>
                                      <b>
                                        📍 Ubicación:
                                      </b>{" "}

                                      {[
                                        profesional.municipio,
                                        profesional.estado
                                      ]
                                        .filter(Boolean)
                                        .join(", ")}
                                    </span>
                                  )}

                                  {!!modalidades.length && (
                                    <span>
                                      <b>
                                        Modalidad:
                                      </b>{" "}

                                      {modalidades.join(" / ")}
                                    </span>
                                  )}

                                  {money(
                                    profesional
                                      .precio_presencial
                                  ) && (
                                    <span>
                                      <b>
                                        Presencial:
                                      </b>{" "}

                                      {money(
                                        profesional
                                          .precio_presencial
                                      )}
                                    </span>
                                  )}

                                  {money(
                                    profesional
                                      .precio_videollamada
                                  ) && (
                                    <span>
                                      <b>
                                        Videollamada:
                                      </b>{" "}

                                      {money(
                                        profesional
                                          .precio_videollamada
                                      )}
                                    </span>
                                  )}

                                  {profesional.disponibilidad && (
                                    <span style={styles.availabilityText}>
                                      <b>
                                        📅 Disponibilidad:
                                      </b>{" "}

                                      {profesional.disponibilidad}
                                    </span>
                                  )}

                                  {profesional
                                    ?.compatibilidad
                                    ?.calculada && (
                                    <div style={styles.rankingBreakdown}>
                                      <span>
                                        🎯 Áreas{" "}
                                        <b>
                                          {
                                            profesional
                                              .compatibilidad
                                              .areas
                                              ?.puntos || 0
                                          }
                                          /45
                                        </b>
                                      </span>

                                      <span>
                                        💰 Economía{" "}
                                        <b>
                                          {
                                            profesional
                                              .compatibilidad
                                              .economica
                                              ?.puntos || 0
                                          }
                                          /25
                                        </b>
                                      </span>

                                      <span>
                                        📍 Ubicación{" "}
                                        <b>
                                          {
                                            profesional
                                              .compatibilidad
                                              .ubicacion
                                              ?.puntos || 0
                                          }
                                          /20
                                        </b>
                                      </span>

                                      <span>
                                        💻 Modalidad{" "}
                                        <b>
                                          {
                                            profesional
                                              .compatibilidad
                                              .modalidad
                                              ?.puntos || 0
                                          }
                                          /10
                                        </b>
                                      </span>
                                    </div>
                                  )}
                                </div>
                              </button>
                            );
                          }
                        )}
                      </div>
                      )}

                      {rankingActivo &&
                        !cargandoProfesionales &&
                        !profesionales.length && (
                        <div style={styles.empty}>
                          No hay profesionales con perfil completo y disponibilidad activa para canalización.
                        </div>
                      )}

                      <div style={styles.actionsRight}>
                        <button
                          type="button"
                          style={{
                            ...styles.sendOptionsButton,
                            ...(procesando
                              ? styles.buttonDisabled
                              : {})
                          }}
                          disabled={
                            procesando
                          }
                          onClick={
                            enviarOpciones
                          }
                        >
                          {procesando
                            ? "Enviando..."

                            : seleccionProfesionales.length

                            ? detalle.opciones?.length
                              ? `Actualizar y enviar ${seleccionProfesionales.length} opción(es)`
                              : `Enviar ${seleccionProfesionales.length} opción(es) al empleado`

                            : "Enviar opciones al empleado"}
                        </button>
                      </div>

                      {enlaceEmpleado && (
                        <div
                          ref={enlaceRef}
                          style={styles.publicLinkBox}
                        >
                          <div style={styles.publicLinkText}>
                            <strong>
                              Enlace para el empleado
                            </strong>

                            <span>
                              Copia este enlace y envíaselo al empleado por correo, WhatsApp o mensaje.
                            </span>

                            <code style={styles.publicLinkCode}>
                              {enlaceEmpleado}
                            </code>
                          </div>

                          <button
                            type="button"
                            style={styles.secondaryButton}
                            onClick={async () => {
                              try {
                                await navigator.clipboard.writeText(
                                  enlaceEmpleado
                                );

                                setMensaje(
                                  "Enlace copiado al portapapeles."
                                );
                              } catch {
                                window.prompt(
                                  "Copia este enlace:",
                                  enlaceEmpleado
                                );
                              }
                            }}
                          >
                            📋 Copiar enlace
                          </button>
                        </div>
                      )}
                    </>
                  )}

                  {!!detalle.opciones?.length && (
                    <div style={styles.sentOptions}>
                      <strong>
                        Opciones enviadas actualmente
                      </strong>

                      {detalle.opciones
                        .filter(
                          opcion =>
                            Number(
                              opcion.enviado
                            ) === 1 &&
                            ![
                              "rechazado",
                              "rechazada"
                            ].includes(
                              String(
                                opcion
                                  .estado_respuesta_profesional ||
                                ""
                              )
                                .trim()
                                .toLowerCase()
                            )
                        )
                        .map(
                        opcion => {

                          const profesional =
                            enriquecerOpcion(
                              opcion
                            );

                          const foto =
                            obtenerFotoProfesional(
                              profesional.foto_url
                            );

                          const modalidades =
                            [
                              Number(
                                profesional
                                  .modalidad_presencial
                              ) === 1
                                ? "Presencial"
                                : null,

                              Number(
                                profesional
                                  .modalidad_videollamada
                              ) === 1
                                ? "Videollamada"
                                : null
                            ].filter(Boolean);

                          return (
                            <div
                              key={
                                opcion.id_opcion
                              }
                              style={styles.sentOptionRow}
                            >
                              <div style={styles.sentOptionMain}>
                                <div style={styles.sentAvatar}>
                                  {foto ? (
                                    <img
                                      src={foto}
                                      alt={profesional.nombre}
                                      style={styles.sentAvatarImage}
                                    />
                                  ) : (
                                    String(
                                      profesional.nombre ||
                                      "P"
                                    )
                                      .charAt(0)
                                      .toUpperCase()
                                  )}
                                </div>

                                <div style={styles.sentOptionText}>
                                  <strong>
                                    {profesional.nombre}
                                  </strong>

                                  <span>
                                    {profesional.especialidad ||
                                      "Sin especialidad registrada"}
                                  </span>

                                  {profesional
                                    .anos_experiencia !==
                                    null &&
                                    profesional
                                      .anos_experiencia !==
                                      undefined && (
                                      <small>
                                        {profesional.anos_experiencia} año(s) de experiencia
                                      </small>
                                    )}

                                  {!!profesional
                                    .areas_atencion
                                    ?.length && (
                                    <div style={styles.sentAreas}>
                                      {profesional
                                        .areas_atencion
                                        .slice(0, 4)
                                        .map(
                                          area => (
                                            <span
                                              key={area}
                                              style={styles.sentAreaChip}
                                            >
                                              {area}
                                            </span>
                                          )
                                        )}
                                    </div>
                                  )}

                                  {(profesional.municipio ||
                                    profesional.estado) && (
                                    <small>
                                      📍{" "}
                                      {[
                                        profesional.municipio,
                                        profesional.estado
                                      ]
                                        .filter(Boolean)
                                        .join(", ")}
                                    </small>
                                  )}

                                  {!!modalidades.length && (
                                    <small>
                                      {modalidades.join(" / ")}
                                    </small>
                                  )}

                                  {(money(
                                    profesional
                                      .precio_presencial
                                  ) ||
                                    money(
                                      profesional
                                        .precio_videollamada
                                    )) && (
                                    <small>
                                      💰{" "}
                                      {money(
                                        profesional
                                          .precio_presencial
                                      )
                                        ? `Presencial: ${money(
                                            profesional
                                              .precio_presencial
                                          )}`
                                        : ""}
                                      {money(
                                        profesional
                                          .precio_presencial
                                      ) &&
                                      money(
                                        profesional
                                          .precio_videollamada
                                      )
                                        ? " · "
                                        : ""}
                                      {money(
                                        profesional
                                          .precio_videollamada
                                      )
                                        ? `Videollamada: ${money(
                                            profesional
                                              .precio_videollamada
                                          )}`
                                        : ""}
                                    </small>
                                  )}
                                </div>
                              </div>

                              {Number(
                                opcion.seleccionado
                              ) === 1 && (
                                <span style={styles.selectedBadge}>
                                  ✓ Elegido
                                </span>
                              )}
                            </div>
                          );
                        }
                      )}
                    </div>
                  )}
                </Seccion>
                </div>

                {/* ====================================
                    ELECCIÓN DEL EMPLEADO
                ==================================== */}

                <Seccion
                  titulo="Elección del empleado"
                  subtitulo={
                    detalle
                      .canalizacion
                      ?.id_opcion_elegida
                      ? "El empleado ya realizó su elección"
                      : detalle.opciones?.some(
                          opcion =>
                            [
                              "rechazado",
                              "rechazada"
                            ].includes(
                              String(
                                opcion
                                  .estado_respuesta_profesional ||
                                ""
                              )
                                .trim()
                                .toLowerCase()
                            )
                        )
                        ? "Profesional rechazó · requiere nuevas opciones"
                        : "Pendiente"
                  }
                  abierta={
                    abiertas.eleccion
                  }
                  onToggle={() =>
                    setAbiertas(
                      prev => ({
                        ...prev,

                        eleccion:
                          !prev.eleccion
                      })
                    )
                  }
                >
                  {detalle
                    .canalizacion
                    ?.id_opcion_elegida ? (
                    <div style={styles.selectionSuccess}>
                      <strong>
                        ✓ Selección registrada
                      </strong>

                      <span>
                        Fecha:{" "}

                        {formatearFecha(
                          detalle
                            .canalizacion
                            ?.fecha_eleccion
                        )}
                      </span>

                      {detalle.opciones
                        ?.filter(
                          opcion =>
                            Number(
                              opcion.seleccionado
                            ) === 1
                        )
                        .map(
                          opcion => (
                            <div
                              key={
                                opcion.id_opcion
                              }
                              style={styles.chosenProfessional}
                            >
                              <strong>
                                {
                                  opcion
                                    .nombre_profesional
                                }
                              </strong>

                              <span>
                                {opcion.especialidad ||
                                  "Especialidad no registrada"}
                              </span>

                              <span>
                                {opcion.tipo_profesional ===
                                "mirrorsoul"
                                  ? "Psicólogo MirrorSoul"
                                  : "Profesional externo"}
                              </span>
                            </div>
                          )
                        )}
                    </div>

                  ) : detalle.opciones?.some(
                      opcion =>
                        [
                          "rechazado",
                          "rechazada"
                        ].includes(
                          String(
                            opcion
                              .estado_respuesta_profesional ||
                            ""
                          )
                            .trim()
                            .toLowerCase()
                        )
                    ) ? (
                    <div style={styles.rejectedHistoryBox}>
                      <strong style={styles.rejectedHistoryTitle}>
                        ⚠️ Profesional rechazó la canalización
                      </strong>

                      <span style={styles.rejectedHistoryHelp}>
                        El empleado había seleccionado un profesional, pero el profesional rechazó esta canalización. RH debe enviar nuevas opciones.
                      </span>

                      {detalle.opciones
                        .filter(
                          opcion =>
                            [
                              "rechazado",
                              "rechazada"
                            ].includes(
                              String(
                                opcion
                                  .estado_respuesta_profesional ||
                                ""
                              )
                                .trim()
                                .toLowerCase()
                            )
                        )
                        .map(
                          opcion => (
                            <div
                              key={`eleccion-rechazo-${opcion.id_opcion}`}
                              style={styles.rejectedProfessionalRow}
                            >
                              <div>
                                <strong>
                                  {opcion.nombre_profesional ||
                                    "Profesional"}
                                </strong>

                                <div style={styles.rejectedReason}>
                                  <b>Motivo:</b>{" "}
                                  {opcion.motivo_rechazo_profesional ||
                                    "No se registró un motivo."}
                                </div>

                                {opcion.observacion_respuesta_profesional && (
                                  <div style={styles.rejectedObservation}>
                                    <b>Observación:</b>{" "}
                                    {opcion.observacion_respuesta_profesional}
                                  </div>
                                )}

                                {opcion.fecha_respuesta_profesional && (
                                  <small>
                                    Fecha del rechazo:{" "}
                                    {formatearFecha(
                                      opcion.fecha_respuesta_profesional
                                    )}
                                  </small>
                                )}
                              </div>
                            </div>
                          )
                        )}

                      <div style={{ marginTop: 10 }}>
                        <strong>
                          Acción requerida: selecciona y envía nuevas opciones al empleado.
                        </strong>
                      </div>
                    </div>

                  ) : (
                    <div style={styles.pendingBox}>
                      <strong>
                        Pendiente de elección
                      </strong>

                      <span>
                        El empleado todavía no ha elegido una de las opciones enviadas.
                      </span>

                      <span>
                        Enviadas:{" "}

                        {formatearFecha(
                          detalle
                            .canalizacion
                            ?.fecha_envio_opciones
                        )}
                      </span>

                      <span>
                        Seguimiento:{" "}

                        {formatearFecha(
                          detalle
                            .canalizacion
                            ?.fecha_limite_seguimiento
                        )}
                      </span>
                    </div>
                  )}
                </Seccion>

                {/* ====================================
                    SEGUIMIENTOS RH
                ==================================== */}

                <Seccion
                  titulo="Seguimientos RH"
                  subtitulo={`${detalle.seguimientos?.length || 0} registro(s)`}
                  abierta={
                    abiertas.seguimiento
                  }
                  alerta={
                    Number(
                      detalle
                        .canalizacion
                        ?.seguimiento_requerido
                    ) === 1
                  }
                  onToggle={() =>
                    setAbiertas(
                      prev => ({
                        ...prev,

                        seguimiento:
                          !prev.seguimiento
                      })
                    )
                  }
                >
                  {![
                    "cerrada",
                    "cancelada"
                  ].includes(
                    detalle
                      .canalizacion
                      ?.estatus
                  ) && (
                    <form
                      onSubmit={
                        guardarSeguimiento
                      }
                      style={styles.followForm}
                    >
                      <div style={styles.formGrid}>
                        <label style={styles.label}>
                          Tipo de seguimiento

                          <select
                            style={styles.input}
                            value={
                              seguimiento
                                .tipo_seguimiento
                            }
                            onChange={e =>
                              setSeguimiento(
                                prev => ({
                                  ...prev,

                                  tipo_seguimiento:
                                    e.target.value
                                })
                              )
                            }
                          >
                            {TIPOS_SEGUIMIENTO.map(
                              item => (
                                <option
                                  key={item.value}
                                  value={item.value}
                                >
                                  {item.label}
                                </option>
                              )
                            )}
                          </select>
                        </label>

                        <label style={styles.label}>
                          Motivo de no selección

                          <select
                            style={styles.input}
                            value={
                              seguimiento
                                .motivo_no_seleccion
                            }
                            onChange={e =>
                              setSeguimiento(
                                prev => ({
                                  ...prev,

                                  motivo_no_seleccion:
                                    e.target.value
                                })
                              )
                            }
                          >
                            {MOTIVOS_NO_SELECCION.map(
                              item => (
                                <option
                                  key={item.value}
                                  value={item.value}
                                >
                                  {item.label}
                                </option>
                              )
                            )}
                          </select>
                        </label>
                      </div>

                      <label style={styles.label}>
                        Observación administrativa

                        <textarea
                          style={styles.textarea}
                          value={
                            seguimiento
                              .observacion
                          }
                          onChange={e =>
                            setSeguimiento(
                              prev => ({
                                ...prev,

                                observacion:
                                  e.target.value
                              })
                            )
                          }
                          placeholder="Ej. Se contactó al empleado. Indica que las opciones están fuera de su presupuesto y solicita alternativas..."
                        />
                      </label>

                      <div style={styles.actionsRight}>
                        <button
                          type="submit"
                          style={styles.primaryButton}
                          disabled={procesando}
                        >
                          {procesando
                            ? "Guardando..."
                            : "Guardar seguimiento"}
                        </button>
                      </div>
                    </form>
                  )}

                  <div style={styles.timeline}>
                    {!detalle.seguimientos?.length ? (
                      <div style={styles.empty}>
                        Todavía no hay seguimientos registrados.
                      </div>

                    ) : (
                      detalle.seguimientos.map(
                        item => (
                          <div
                            key={
                              item.id_seguimiento
                            }
                            style={styles.timelineItem}
                          >
                            <div style={styles.timelineDot} />

                            <div style={styles.timelineContent}>
                              <div style={styles.timelineTop}>
                                <strong>
                                  {TIPOS_SEGUIMIENTO.find(
                                    tipo =>
                                      tipo.value ===
                                      item.tipo_seguimiento
                                  )?.label ||
                                    item.tipo_seguimiento}
                                </strong>

                                <span>
                                  {formatearFecha(
                                    item.fecha_seguimiento
                                  )}
                                </span>
                              </div>

                              {item.motivo_no_seleccion && (
                                <span>
                                  Motivo:{" "}

                                  {
                                    MOTIVOS_NO_SELECCION.find(
                                      motivo =>
                                        motivo.value ===
                                        item
                                          .motivo_no_seleccion
                                    )?.label ||
                                    item
                                      .motivo_no_seleccion
                                  }
                                </span>
                              )}

                              {item.observacion && (
                                <p>
                                  {item.observacion}
                                </p>
                              )}

                              <small>
                                Registrado por:{" "}

                                {item.usuario_rh_nombre ||
                                  "RH"}
                              </small>
                            </div>
                          </div>
                        )
                      )
                    )}
                  </div>
                </Seccion>

                {/* ====================================
                    HISTORIAL
                ==================================== */}

                <Seccion
                  titulo="Historial"
                  subtitulo="Evidencia administrativa"
                  abierta={
                    abiertas.historial
                  }
                  onToggle={() =>
                    setAbiertas(
                      prev => ({
                        ...prev,

                        historial:
                          !prev.historial
                      })
                    )
                  }
                >
                  <div style={styles.timeline}>
                    {!detalle.historial?.length ? (
                      <div style={styles.empty}>
                        Sin movimientos registrados.
                      </div>

                    ) : (
                      detalle.historial.map(
                        item => (
                          <div
                            key={
                              item.id_historial
                            }
                            style={styles.timelineItem}
                          >
                            <div style={styles.timelineDot} />

                            <div style={styles.timelineContent}>
                              <div style={styles.timelineTop}>
                                <strong>
                                  {item.evento}
                                </strong>

                                <span>
                                  {formatearFecha(
                                    item.fecha_evento
                                  )}
                                </span>
                              </div>

                              {item.detalle && (
                                <p>
                                  {item.detalle}
                                </p>
                              )}

                              {item.usuario_nombre && (
                                <small>
                                  {item.usuario_nombre}
                                </small>
                              )}
                            </div>
                          </div>
                        )
                      )
                    )}
                  </div>
                </Seccion>

                {/* ====================================
                    CIERRE Y CANCELACIÓN
                ==================================== */}

                {![
                  "cerrada",
                  "cancelada"
                ].includes(
                  detalle
                    .canalizacion
                    ?.estatus
                ) && (
                  <div style={styles.finalActions}>

                    <div style={styles.finalActionCard}>
                      <strong>
                        Cerrar canalización
                      </strong>

                      <p>
                        Cierra únicamente el proceso administrativo de RH.
                      </p>

                      <textarea
                        style={styles.smallTextarea}
                        value={
                          cierreObservacion
                        }
                        onChange={e =>
                          setCierreObservacion(
                            e.target.value
                          )
                        }
                        placeholder="Observación de cierre..."
                      />

                      <button
                        type="button"
                        style={styles.closeButton}
                        onClick={
                          cerrarCanalizacion
                        }
                        disabled={procesando}
                      >
                        Cerrar canalización
                      </button>
                    </div>

                    {!detalle
                      .canalizacion
                      ?.id_opcion_elegida && (
                      <div style={styles.finalActionCard}>
                        <strong>
                          Cancelar
                        </strong>

                        <p>
                          Solo si la canalización ya no debe continuar.
                        </p>

                        <textarea
                          style={styles.smallTextarea}
                          value={
                            motivoCancelacion
                          }
                          onChange={e =>
                            setMotivoCancelacion(
                              e.target.value
                            )
                          }
                          placeholder="Motivo obligatorio..."
                        />

                        <button
                          type="button"
                          style={styles.cancelButton}
                          onClick={
                            cancelarCanalizacion
                          }
                          disabled={procesando}
                        >
                          Cancelar canalización
                        </button>
                      </div>
                    )}
                  </div>
                )}

              </>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
const styles = {
  headerActions: {
    display: "flex",
    gap: 10,
    alignItems: "center",
    justifyContent: "flex-end",
    flexWrap: "wrap"
  },

  sendOptionsTopButton: {
    border: "1px solid #1d4ed8",
    borderRadius: 10,
    padding: "11px 16px",
    fontWeight: 800,
    cursor: "pointer",
    background: "#2563eb",
    color: "#fff",
    whiteSpace: "nowrap"
  },

  rhDecisionReason: {
    marginTop: 10,
    padding: "10px 12px",
    borderRadius: 10,
    background: "#fff",
    border: "1px solid #e2e8f0"
  },

  backButton: {
    border: "1px solid #d0d5dd",
    background: "#fff",
    color: "#344054",
    borderRadius: "9px",
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: "800",
    fontSize: "13px",
    marginBottom: "18px",
    boxShadow:
      "0 1px 3px rgba(16,24,40,.05)"
  },

  page: {
    minHeight: "100vh",
    background: "#f5f7fb",
    padding: "18px 14px",
    fontFamily:
      "Inter, Arial, sans-serif",
    color: "#182230"
  },

  container: {
    maxWidth: "1450px",
    margin: "0 auto"
  },

  topRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "12px",
    marginBottom: "12px",
    flexWrap: "wrap"
  },

  title: {
    margin: 0,
    fontSize: "26px",
    fontWeight: "850",
    letterSpacing: "-0.5px"
  },

  subtitle: {
    margin: "7px 0 0",
    color: "#667085",
    fontSize: "14px"
  },

  employeeCard: {
    background: "#fff",
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "12px 15px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "15px",
    marginBottom: "10px",
    boxShadow:
      "0 2px 10px rgba(16,24,40,.04)"
  },

  employeeName: {
    fontSize: "17px"
  },

  employeeMeta: {
    color: "#667085",
    fontSize: "13px",
    marginTop: "5px"
  },

  rhBadge: {
    background: "#eef4ff",
    color: "#3538cd",
    borderRadius: "999px",
    padding: "7px 12px",
    fontWeight: "800",
    fontSize: "12px"
  },

  privacyBox: {
    display: "flex",
    gap: "10px",
    flexWrap: "wrap",
    alignItems: "center",
    background: "#f8f9fc",
    border: "1px solid #d5d9eb",
    color: "#363f72",
    padding: "9px 12px",
    borderRadius: "9px",
    fontSize: "12px",
    marginBottom: "10px"
  },

  errorBox: {
    background: "#fef3f2",
    border: "1px solid #fecdca",
    color: "#b42318",
    padding: "12px 15px",
    borderRadius: "10px",
    marginBottom: "14px",
    fontSize: "14px",
    fontWeight: "650"
  },

  successBox: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    color: "#067647",
    padding: "12px 15px",
    borderRadius: "10px",
    marginBottom: "14px",
    fontSize: "14px",
    fontWeight: "650"
  },

  primaryButton: {
    border: "none",
    background: "#155eef",
    color: "#fff",
    borderRadius: "9px",
    padding: "11px 16px",
    cursor: "pointer",
    fontWeight: "800",
    fontSize: "13px"
  },

  secondaryButton: {
    background: "#fff",
    border: "1px solid #d0d5dd",
    color: "#344054",
    borderRadius: "9px",
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: "750"
  },

  systemIntro: {
    display: "flex",
    gap: "9px",
    alignItems: "flex-start",
    background: "#f5f8ff",
    border: "1px solid #c7d7fe",
    borderRadius: "12px",
    padding: "10px",
    marginBottom: "10px"
  },

  systemIcon: {
    width: "38px",
    height: "38px",
    borderRadius: "10px",
    background: "#e0eaff",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "19px",
    flexShrink: 0
  },

  noRecommendations: {
    border: "1px dashed #b2ccff",
    background: "#fcfcfd",
    borderRadius: "11px",
    padding: "20px",
    display: "flex",
    flexDirection: "column",
    gap: "7px",
    color: "#475467",
    textAlign: "center"
  },

  futureInfo: {
    fontSize: "12px",
    color: "#667085"
  },

  recommendationToggle: {
    width: "100%",
    border: "none",
    background: "transparent",
    padding: "11px 13px",
    cursor: "pointer",
    textAlign: "left",
    color: "#182230"
  },

  recommendationSummary: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "12px"
  },

  recommendationSummaryRight: {
    display: "flex",
    alignItems: "center",
    justifyContent: "flex-end",
    gap: "8px",
    flexWrap: "wrap",
    flexShrink: 0
  },

  recommendationTitleCompact: {
    margin: "6px 0 0",
    fontSize: "15px",
    lineHeight: "1.25"
  },

  testNameCompact: {
    display: "block",
    marginTop: "3px",
    color: "#667085",
    fontSize: "11px",
    fontWeight: "600"
  },

  pendingMiniBadge: {
    background: "#fff7ed",
    color: "#b54708",
    borderRadius: "999px",
    padding: "3px 7px",
    fontSize: "9px",
    fontWeight: "800"
  },

  reviewedMiniBadge: {
    background: "#f2f4f7",
    color: "#475467",
    borderRadius: "999px",
    padding: "3px 7px",
    fontSize: "9px",
    fontWeight: "800"
  },

  scoreBadge: {
    background: "#f2f4f7",
    color: "#344054",
    borderRadius: "999px",
    padding: "4px 8px",
    fontSize: "10px",
    fontWeight: "800"
  },

  compactDate: {
    color: "#98a2b3",
    fontSize: "10px",
    whiteSpace: "nowrap"
  },

  openIndicator: {
    color: "#667085",
    fontSize: "10px"
  },

  recommendationBody: {
    borderTop: "1px solid #eaecf0",
    padding: "12px 13px",
    background: "#fff"
  },

  compactMetaGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(130px,1fr))",
    gap: "8px",
    marginBottom: "10px"
  },

  rhTestResultBox: {
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    borderRadius: "9px",
    padding: "10px",
    marginTop: "8px"
  },

  rhTestResultHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "8px",
    marginBottom: "7px"
  },

  versionBadge: {
    background: "#eef4ff",
    color: "#3538cd",
    borderRadius: "999px",
    padding: "3px 7px",
    fontSize: "9px",
    fontWeight: "800"
  },

  compactParagraph: {
    margin: "5px 0",
    lineHeight: "1.45",
    color: "#475467",
    fontSize: "12px"
  },

  aiBoxCompact: {
    background: "#f5f8ff",
    border: "1px solid #c7d7fe",
    borderRadius: "9px",
    padding: "10px",
    marginTop: "9px"
  },

  aiTextCompact: {
    margin: "7px 0",
    lineHeight: "1.45",
    whiteSpace: "pre-wrap",
    color: "#344054",
    fontSize: "12px"
  },

  decisionBoxCompact: {
    borderTop: "1px solid #eaecf0",
    marginTop: "10px",
    paddingTop: "10px"
  },

  labelCompact: {
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    fontWeight: "750",
    fontSize: "12px",
    color: "#344054",
    marginBottom: "9px"
  },

  sendOptionsButton: {
    border: "none",
    background: "#155eef",
    color: "#fff",
    borderRadius: "9px",
    padding: "11px 16px",
    cursor: "pointer",
    fontWeight: "850",
    fontSize: "13px",
    boxShadow:
      "0 2px 5px rgba(21,94,239,.18)"
  },

  buttonDisabled: {
    opacity: 0.55,
    cursor: "not-allowed"
  },

  recommendationsList: {
    display: "flex",
    flexDirection: "column",
    gap: "8px"
  },

  recommendationCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "10px",
    padding: "0",
    background: "#fff",
    overflow: "hidden"
  },

  recommendationPending: {
    border: "1px solid #fdb022",
    boxShadow:
      "0 2px 8px rgba(247,144,9,.08)"
  },

  recommendationTop: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "12px",
    flexWrap: "wrap"
  },

  recommendationTitle: {
    margin: "8px 0 0",
    fontSize: "17px"
  },

  testName: {
    margin: "5px 0 0",
    color: "#475467",
    fontSize: "13px",
    fontWeight: "650",
    lineHeight: "1.4"
  },

  badgeRow: {
    display: "flex",
    gap: "7px",
    flexWrap: "wrap"
  },

  systemBadge: {
    background: "#eef4ff",
    color: "#3538cd",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  rhDetectedBadge: {
    background: "#f0f9ff",
    color: "#026aa2",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  dangerBadge: {
    background: "#fef3f2",
    color: "#b42318",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  warningBadge: {
    background: "#fffaeb",
    color: "#b54708",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  okBadge: {
    background: "#ecfdf3",
    color: "#067647",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  referenceBox: {
    background: "#f9fafb",
    border: "1px solid #eaecf0",
    borderRadius: "9px",
    padding: "9px 12px",
    display: "flex",
    flexDirection: "column",
    gap: "3px",
    fontSize: "11px",
    color: "#667085"
  },

  recommendationDataGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(180px,1fr))",
    gap: "10px",
    marginTop: "13px"
  },

  detectedResult: {
    background: "#f9fafb",
    border: "1px solid #eaecf0",
    borderRadius: "9px",
    padding: "12px",
    marginTop: "12px"
  },

  nomResultBox: {
    marginTop: "12px",
    padding: "14px",
    background: "#fff7ed",
    border: "1px solid #fed7aa",
    borderRadius: "10px"
  },

  nomResultHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "10px",
    flexWrap: "wrap"
  },

  nomResultText: {
    margin: "10px 0",
    color: "#7c2d12",
    lineHeight: "1.5",
    fontSize: "13px"
  },

  nomRecommendation: {
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    background: "#fff",
    padding: "10px",
    borderRadius: "8px",
    color: "#475467",
    fontSize: "12px"
  },

  nomMeta: {
    display: "flex",
    flexWrap: "wrap",
    gap: "14px",
    marginTop: "10px",
    color: "#667085",
    fontSize: "11px"
  },

  factorBox: {
    marginTop: "12px"
  },

  factorList: {
    display: "flex",
    flexWrap: "wrap",
    gap: "6px",
    marginTop: "7px"
  },

  factorTag: {
    background: "#f2f4f7",
    color: "#344054",
    padding: "5px 8px",
    borderRadius: "999px",
    fontSize: "11px"
  },

  aiBox: {
    background: "#f5f8ff",
    border: "1px solid #c7d7fe",
    borderRadius: "11px",
    padding: "14px",
    marginTop: "12px"
  },

  aiHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "10px",
    alignItems: "center"
  },

  aiLabel: {
    background: "#e0eaff",
    color: "#3538cd",
    borderRadius: "999px",
    padding: "4px 8px",
    fontSize: "10px",
    fontWeight: "800"
  },

  aiText: {
    margin: "10px 0",
    lineHeight: "1.55",
    whiteSpace: "pre-wrap",
    color: "#344054",
    fontSize: "13px"
  },

  aiEmpty: {
    color: "#667085",
    fontStyle: "italic",
    fontSize: "13px"
  },

  aiNotice: {
    color: "#667085"
  },

  decisionBox: {
    borderTop: "1px solid #eaecf0",
    marginTop: "14px",
    paddingTop: "14px"
  },

  decisionButtons: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap",
    justifyContent: "flex-end"
  },

  approveButton: {
    border: "none",
    background: "#067647",
    color: "#fff",
    borderRadius: "8px",
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: "800"
  },

  followButton: {
    border: "1px solid #fedf89",
    background: "#fffaeb",
    color: "#b54708",
    borderRadius: "8px",
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: "800"
  },

  noButton: {
    border: "1px solid #d0d5dd",
    background: "#fff",
    color: "#344054",
    borderRadius: "8px",
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: "800"
  },

  reviewedBox: {
    background: "#f9fafb",
    borderRadius: "9px",
    padding: "12px",
    marginTop: "13px",
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    color: "#475467",
    fontSize: "12px"
  },

  newCard: {
    background: "#fff",
    border: "1px solid #d0d5dd",
    borderRadius: "14px",
    padding: "20px",
    marginBottom: "18px",
    boxShadow:
      "0 3px 12px rgba(16,24,40,.04)"
  },

  manualHeader: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: "12px",
    flexWrap: "wrap",
    marginBottom: "15px"
  },

  cardTitle: {
    margin: 0,
    fontSize: "18px"
  },

  manualDescription: {
    color: "#667085",
    fontSize: "12px",
    margin: "5px 0 0"
  },

  detectTypeBox: {
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    background: "#f0f9ff",
    border: "1px solid #b9e6fe",
    color: "#026aa2",
    borderRadius: "10px",
    padding: "12px",
    marginBottom: "15px"
  },

  formGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(240px,1fr))",
    gap: "14px"
  },

  label: {
    display: "flex",
    flexDirection: "column",
    gap: "7px",
    fontWeight: "750",
    fontSize: "13px",
    color: "#344054",
    marginBottom: "14px"
  },

  optional: {
    fontWeight: "500",
    color: "#98a2b3",
    fontSize: "11px"
  },

  input: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "9px",
    padding: "10px 11px",
    fontSize: "14px",
    background: "#fff",
    outline: "none"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    minHeight: "95px",
    resize: "vertical",
    border: "1px solid #d0d5dd",
    borderRadius: "9px",
    padding: "11px",
    fontFamily: "inherit",
    fontSize: "14px",
    outline: "none"
  },

  smallTextarea: {
    width: "100%",
    boxSizing: "border-box",
    minHeight: "75px",
    resize: "vertical",
    border: "1px solid #d0d5dd",
    borderRadius: "8px",
    padding: "9px",
    fontFamily: "inherit"
  },

  actionsRight: {
    display: "flex",
    justifyContent: "flex-end",
    marginTop: "8px"
  },

  layout: {
    display: "grid",
    gridTemplateColumns:
      "minmax(260px,330px) minmax(0,1fr)",
    gap: "18px",
    alignItems: "start"
  },

  sidebar: {
    background: "#fff",
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    overflow: "hidden",
    position: "sticky",
    top: "20px"
  },

  sidebarHeader: {
    padding: "15px 16px",
    borderBottom: "1px solid #eaecf0",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center"
  },

  counter: {
    background: "#f2f4f7",
    borderRadius: "999px",
    padding: "4px 8px",
    fontSize: "11px",
    fontWeight: "800"
  },

  canalizacionItem: {
    width: "100%",
    textAlign: "left",
    border: "none",
    borderBottom: "1px solid #f2f4f7",
    background: "#fff",
    padding: "10px 12px",
    cursor: "pointer",
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    color: "#182230"
  },

  canalizacionItemActive: {
    background: "#eff4ff",
    boxShadow:
      "inset 3px 0 0 #155eef"
  },

  itemTop: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "7px"
  },

  sourceLine: {
    display: "flex",
    marginTop: "2px"
  },

  systemMiniBadge: {
    background: "#eef4ff",
    color: "#3538cd",
    padding: "3px 7px",
    borderRadius: "999px",
    fontSize: "9px",
    fontWeight: "800"
  },

  rhMiniBadge: {
    background: "#f0f9ff",
    color: "#026aa2",
    padding: "3px 7px",
    borderRadius: "999px",
    fontSize: "9px",
    fontWeight: "800"
  },

  itemOrigin: {
    color: "#475467",
    fontSize: "12px"
  },

  itemReference: {
    color: "#667085",
    fontSize: "10px"
  },

  itemStatus: {
    fontSize: "12px",
    fontWeight: "750",
    color: "#155eef"
  },

  itemDate: {
    color: "#98a2b3",
    fontSize: "11px"
  },

  alertBadge: {
    background: "#fffaeb",
    color: "#b54708",
    padding: "3px 6px",
    borderRadius: "999px",
    fontSize: "9px",
    fontWeight: "850"
  },

  content: {
    minWidth: 0
  },

  empty: {
    padding: "22px",
    textAlign: "center",
    color: "#667085",
    fontSize: "13px"
  },

  emptyLarge: {
    minHeight: "320px",
    background: "#fff",
    border: "1px dashed #d0d5dd",
    borderRadius: "14px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "column",
    gap: "9px",
    color: "#667085",
    textAlign: "center",
    padding: "20px"
  },

  emptyIcon: {
    fontSize: "38px"
  },

  loading: {
    padding: "50px",
    textAlign: "center",
    color: "#667085"
  },

  detailHeader: {
    background: "#fff",
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "12px 15px",
    marginBottom: "8px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "15px",
    flexWrap: "wrap"
  },

  detailTitle: {
    margin: 0,
    fontSize: "21px"
  },

  detailBadges: {
    display: "flex",
    gap: "7px",
    flexWrap: "wrap",
    marginTop: "8px"
  },

  statusBadge: {
    background: "#eff8ff",
    color: "#175cd3",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  alertBadgeLarge: {
    background: "#fffaeb",
    color: "#b54708",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  followAlert: {
    background: "#fffaeb",
    border: "1px solid #fedf89",
    color: "#93370d",
    borderRadius: "11px",
    padding: "13px 15px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    marginBottom: "12px"
  },

  section: {
    background: "#fff",
    border: "1px solid #e4e7ec",
    borderRadius: "13px",
    marginBottom: "8px",
    overflow: "hidden"
  },

  sectionHeader: {
    width: "100%",
    border: "none",
    background: "#fff",
    padding: "11px 14px",
    cursor: "pointer",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    textAlign: "left"
  },

  sectionHeaderAlert: {
    background: "#fffaf0"
  },

  sectionTitleWrap: {
    display: "flex",
    flexDirection: "column",
    gap: "3px"
  },

  sectionTitle: {
    fontSize: "14px",
    color: "#182230"
  },

  sectionSubtitle: {
    color: "#667085",
    fontSize: "11px",
    fontWeight: "500"
  },

  chevron: {
    color: "#667085",
    fontSize: "11px"
  },

  sectionBody: {
    padding: "12px 14px",
    borderTop: "1px solid #f2f4f7"
  },

  dataGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(180px,1fr))",
    gap: "12px"
  },

  dataItem: {
    border: "1px solid #eaecf0",
    background: "#fcfcfd",
    borderRadius: "9px",
    padding: "11px",
    display: "flex",
    flexDirection: "column",
    gap: "5px"
  },

  dataLabel: {
    color: "#667085",
    fontSize: "11px",
    fontWeight: "650"
  },

  systemDetailBox: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(200px,1fr))",
    gap: "10px",
    marginTop: "12px",
    background: "#f5f8ff",
    border: "1px solid #c7d7fe",
    borderRadius: "9px",
    padding: "12px"
  },

  reasonBox: {
    marginTop: "12px",
    background: "#f9fafb",
    borderRadius: "9px",
    padding: "12px"
  },

  helper: {
    color: "#667085",
    fontSize: "12px",
    marginTop: 0
  },

  rankingCriteriaBox: {
    marginBottom: 22,
    padding: 18,
    border: "1px solid #dbeafe",
    borderRadius: 14,
    background: "#f8fbff"
  },

  rankingCriteriaHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: 15,
    alignItems: "flex-start",
    marginBottom: 15,
    flexWrap: "wrap"
  },

  rankingActiveBadge: {
    padding: "6px 10px",
    borderRadius: 999,
    background: "#dcfce7",
    color: "#166534",
    fontSize: 12,
    fontWeight: 700
  },

  rankingAreasSection: {
    marginTop: 15,
    display: "flex",
    flexDirection: "column",
    gap: 5
  },

  rankingAreasHelp: {
    color: "#667085",
    fontSize: 12
  },

  rankingAreasGrid: {
    display: "flex",
    flexWrap: "wrap",
    gap: 8,
    marginTop: 10
  },

  rankingAreaButton: {
    border: "1px solid #d1d5db",
    background: "#ffffff",
    color: "#344054",
    borderRadius: 999,
    padding: "8px 12px",
    cursor: "pointer",
    fontSize: 13
  },

  rankingAreaSelected: {
    border: "1px solid #2563eb",
    background: "#eff6ff",
    color: "#1d4ed8",
    fontWeight: 700
  },

  rankingScoreRow: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    flexWrap: "wrap",
    marginTop: 4
  },

  rankingScore: {
    fontSize: 17,
    fontWeight: 850,
    color: "#155eef"
  },

  rankingLevel: {
    padding: "4px 8px",
    borderRadius: 999,
    background: "#f3f4f6",
    color: "#344054",
    fontSize: 10,
    fontWeight: 700
  },

  rankingBreakdown: {
    display: "grid",
    gridTemplateColumns:
      "repeat(2, minmax(0, 1fr))",
    gap: 6,
    marginTop: 8,
    padding: 10,
    borderRadius: 10,
    background: "#f8fafc",
    border: "1px solid #eaecf0",
    fontSize: 10.5
  },

  professionalGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fill,minmax(245px,1fr))",
    gap: "11px"
  },

  professionalCard: {
    border: "1px solid #d0d5dd",
    background: "#fff",
    borderRadius: "11px",
    padding: "13px",
    textAlign: "left",
    cursor: "pointer",
    color: "#182230"
  },

  professionalSelected: {
    border: "2px solid #155eef",
    background: "#f5f8ff"
  },

  professionalTop: {
    display: "flex",
    alignItems: "center",
    gap: "9px"
  },

  avatar: {
    width: "52px",
    height: "52px",
    borderRadius: "50%",
    background: "#e0eaff",
    color: "#3538cd",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "850",
    flexShrink: 0,
    overflow: "hidden",
    border: "2px solid #e0eaff"
  },

  avatarImage: {
    width: "100%",
    height: "100%",
    objectFit: "cover",
    display: "block"
  },

  professionalHeading: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    gap: "2px"
  },

  professionalName: {
    fontSize: "14px",
    lineHeight: 1.25
  },

  professionalType: {
    fontSize: "10px",
    color: "#667085"
  },

  experienceText: {
    fontSize: "10px",
    color: "#475467",
    marginTop: "2px"
  },

  checkboxFake: {
    width: "21px",
    height: "21px",
    borderRadius: "6px",
    border: "1px solid #98a2b3",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#fff",
    background: "#155eef",
    fontWeight: "900",
    flexShrink: 0
  },

  professionalBody: {
    display: "flex",
    flexDirection: "column",
    gap: "6px",
    marginTop: "11px",
    color: "#475467",
    fontSize: "11px"
  },

  professionalDescription: {
    margin: "2px 0",
    color: "#667085",
    lineHeight: 1.45,
    fontSize: "10.5px"
  },

  areasWrap: {
    display: "flex",
    flexWrap: "wrap",
    gap: "5px",
    margin: "2px 0"
  },

  areaChip: {
    padding: "4px 7px",
    borderRadius: "999px",
    background: "#eef4ff",
    border: "1px solid #d1e0ff",
    color: "#1849a9",
    fontSize: "9px",
    fontWeight: "750"
  },

  moreAreas: {
    padding: "4px 7px",
    borderRadius: "999px",
    background: "#f2f4f7",
    color: "#475467",
    fontSize: "9px",
    fontWeight: "750"
  },

  availabilityText: {
    marginTop: "2px",
    lineHeight: 1.4
  },

  infoBox: {
    background: "#f2f4f7",
    borderRadius: "9px",
    padding: "12px",
    color: "#475467",
    fontSize: "13px"
  },

  sentOptions: {
    marginTop: "17px",
    borderTop: "1px solid #eaecf0",
    paddingTop: "14px",
    display: "flex",
    flexDirection: "column",
    gap: "8px"
  },

  sentOptionRow: {
    border: "1px solid #eaecf0",
    borderRadius: "11px",
    padding: "11px 12px",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "10px"
  },

  sentOptionMain: {
    display: "flex",
    alignItems: "flex-start",
    gap: "10px",
    minWidth: 0
  },

  sentAvatar: {
    width: "42px",
    height: "42px",
    borderRadius: "50%",
    background: "#e0eaff",
    color: "#3538cd",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "850",
    flexShrink: 0,
    overflow: "hidden"
  },

  sentAvatarImage: {
    width: "100%",
    height: "100%",
    objectFit: "cover",
    display: "block"
  },

  sentOptionText: {
    display: "flex",
    flexDirection: "column",
    gap: "3px",
    minWidth: 0
  },

  sentAreas: {
    display: "flex",
    flexWrap: "wrap",
    gap: "4px",
    marginTop: "2px"
  },

  sentAreaChip: {
    padding: "3px 6px",
    borderRadius: "999px",
    background: "#eef4ff",
    color: "#1849a9",
    fontSize: "8.5px",
    fontWeight: "750"
  },

  selectedBadge: {
    background: "#ecfdf3",
    color: "#067647",
    borderRadius: "999px",
    padding: "5px 8px",
    fontSize: "10px",
    fontWeight: "850"
  },

  selectionSuccess: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    borderRadius: "10px",
    padding: "14px",
    display: "flex",
    flexDirection: "column",
    gap: "6px",
    color: "#067647"
  },

  chosenProfessional: {
    background: "#fff",
    border: "1px solid #d1fadf",
    borderRadius: "9px",
    padding: "10px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    color: "#344054",
    marginTop: "5px"
  },

  pendingBox: {
    background: "#fffaeb",
    border: "1px solid #fedf89",
    borderRadius: "10px",
    padding: "14px",
    display: "flex",
    flexDirection: "column",
    gap: "6px",
    color: "#93370d"
  },

  followForm: {
    background: "#f9fafb",
    border: "1px solid #eaecf0",
    borderRadius: "10px",
    padding: "14px",
    marginBottom: "18px"
  },

  timeline: {
    display: "flex",
    flexDirection: "column",
    gap: "0"
  },

  timelineItem: {
    display: "flex",
    gap: "11px",
    padding: "11px 0",
    borderBottom: "1px solid #f2f4f7"
  },

  timelineDot: {
    marginTop: "5px",
    width: "9px",
    height: "9px",
    borderRadius: "50%",
    background: "#6172f3",
    flexShrink: 0
  },

  timelineContent: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    fontSize: "12px",
    color: "#475467"
  },

  timelineTop: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    flexWrap: "wrap"
  },

  finalActions: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(260px,1fr))",
    gap: "12px",
    marginTop: "14px"
  },

  finalActionCard: {
    background: "#fff",
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    padding: "15px"
  },

  closeButton: {
    width: "100%",
    marginTop: "10px",
    border: "none",
    background: "#067647",
    color: "#fff",
    borderRadius: "8px",
    padding: "10px",
    fontWeight: "800",
    cursor: "pointer"
  },

  cancelButton: {
    width: "100%",
    marginTop: "10px",
    border: "1px solid #fda29b",
    background: "#fef3f2",
    color: "#b42318",
    borderRadius: "8px",
    padding: "10px",
    fontWeight: "800",
    cursor: "pointer"
  },

  publicLinkBox: {
    marginTop: 14,
    padding: "14px 16px",
    border: "1px solid #cfe0ff",
    background: "#f7faff",
    borderRadius: 14,
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 16,
    flexWrap: "wrap"
  },

  publicLinkText: {
    flex: 1,
    minWidth: 260,
    display: "flex",
    flexDirection: "column",
    gap: 5,
    color: "#53627a",
    fontSize: 13
  },

  publicLinkCode: {
    display: "block",
    marginTop: 4,
    padding: "9px 10px",
    borderRadius: 9,
    background: "#ffffff",
    border: "1px solid #dce5f3",
    color: "#2456d6",
    wordBreak: "break-all",
    fontFamily: "monospace",
    fontSize: 12
  },


  rejectedHistoryBox: {
    marginTop: "14px",
    border: "1px solid #fecdca",
    background: "#fff6f5",
    borderRadius: "12px",
    padding: "14px",
    display: "flex",
    flexDirection: "column",
    gap: "10px"
  },

  rejectedHistoryTitle: {
    color: "#b42318",
    fontSize: "13px"
  },

  rejectedHistoryHelp: {
    color: "#7a271a",
    fontSize: "12px"
  },

  rejectedProfessionalRow: {
    border: "1px solid #fecdca",
    background: "#fff",
    borderRadius: "10px",
    padding: "11px 12px",
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    alignItems: "flex-start"
  },

  rejectedReason: {
    marginTop: "6px",
    color: "#7a271a",
    fontSize: "12px"
  },

  rejectedObservation: {
    marginTop: "5px",
    color: "#475467",
    fontSize: "12px"
  },

  rejectedBadge: {
    background: "#fee4e2",
    color: "#b42318",
    borderRadius: "999px",
    padding: "4px 8px",
    fontSize: "11px",
    fontWeight: "800",
    whiteSpace: "nowrap"
  },

};