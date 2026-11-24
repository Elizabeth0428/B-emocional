// ==================================================
// src/views/PerfilProfesionalPsicologo.jsx
// ==================================================

import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  useNavigate
} from "react-router-dom";

import {
  getToken
} from "../services/AuthService";


// ==================================================
// API
// ==================================================

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;


// ==================================================
// FORMULARIO INICIAL
// ==================================================

const FORM_INICIAL = {

  nombre:
    "",

  correo:
    "",

  cedula_profesional:
    "",

  especialidad:
    "",

  foto_url:
    "",

  descripcion_profesional:
    "",

  anos_experiencia:
    "",

  areas_atencion:
    [],

  modalidad_presencial:
    false,

  modalidad_videollamada:
    false,

  precio_presencial:
    "",

  precio_videollamada:
    "",

  estado:
    "",

  municipio:
    "",

  colonia:
    "",

  codigo_postal:
    "",

  direccion_consultorio:
    "",

  disponibilidad:
    "",

  perfil_profesional_completo:
    0,

  activo_canalizacion:
    0

};


// ==================================================
// COMPONENTE FIELD
// ==================================================

const Field = ({
  label,
  required = false,
  children
}) => {

  return (

    <div style={styles.field}>

      <label style={styles.label}>

        {label}

        {required && (

          <span style={styles.required}>
            {" "}*
          </span>

        )}

      </label>

      {children}

    </div>

  );

};


// ==================================================
// COMPONENTE
// ==================================================

function PerfilProfesionalPsicologo() {

  const navigate =
    useNavigate();


  const token =
    getToken();


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    cargando,
    setCargando
  ] =
    useState(true);


  const [
    guardando,
    setGuardando
  ] =
    useState(false);


  const [
    subiendoFoto,
    setSubiendoFoto
  ] =
    useState(false);


  const [
    buscandoCP,
    setBuscandoCP
  ] =
    useState(false);


  const [
    error,
    setError
  ] =
    useState("");


  const [
    mensaje,
    setMensaje
  ] =
    useState("");


  const [
    areas,
    setAreas
  ] =
    useState([]);


  const [
    colonias,
    setColonias
  ] =
    useState([]);


  const [
    form,
    setForm
  ] =
    useState(
      FORM_INICIAL
    );


  // ==================================================
  // URL DE FOTO
  // ==================================================

  const obtenerUrlFoto =
    foto => {

      if (!foto) {
        return "";
      }


      if (
        foto.startsWith(
          "http://"
        ) ||
        foto.startsWith(
          "https://"
        )
      ) {

        return foto;

      }


      return `${API_URL}${foto}`;

    };


  // ==================================================
  // MAPEAR PERFIL DEL BACKEND
  // ==================================================

  const cargarDatosPerfil =
    perfil => {

      const areasSeleccionadas =
        Array.isArray(
          perfil?.areas_atencion
        )
          ? perfil.areas_atencion
              .map(
                area =>
                  Number(
                    area?.id_area ??
                    area
                  )
              )
              .filter(
                Number.isInteger
              )
          : [];


      setForm({

        nombre:
          perfil?.nombre ||
          "",

        correo:
          perfil?.correo ||
          "",

        cedula_profesional:
          perfil?.cedula_profesional ||
          "",

        especialidad:
          perfil?.especialidad ||
          "",

        foto_url:
          perfil?.foto_url ||
          "",

        descripcion_profesional:
          perfil?.descripcion_profesional ||
          "",

        anos_experiencia:
          perfil?.anos_experiencia ??
          "",

        areas_atencion:
          areasSeleccionadas,

        modalidad_presencial:
          Number(
            perfil?.modalidad_presencial
          ) === 1,

        modalidad_videollamada:
          Number(
            perfil?.modalidad_videollamada
          ) === 1,

        precio_presencial:
          perfil?.precio_presencial ??
          "",

        precio_videollamada:
          perfil?.precio_videollamada ??
          "",

        estado:
          perfil?.estado ||
          "",

        municipio:
          perfil?.municipio ||
          "",

        colonia:
          perfil?.colonia ||
          "",

        codigo_postal:
          perfil?.codigo_postal ||
          "",

        direccion_consultorio:
          perfil?.direccion_consultorio ||
          "",

        disponibilidad:
          perfil?.disponibilidad ||
          "",

        perfil_profesional_completo:
          Number(
            perfil?.perfil_profesional_completo
          ) || 0,

        activo_canalizacion:
          Number(
            perfil?.activo_canalizacion
          ) || 0

      });

    };


  // ==================================================
  // CARGAR PERFIL Y CATÁLOGO
  // ==================================================

  const cargarInformacion =
    async () => {

      try {

        setCargando(true);

        setError("");


        if (!token) {

          throw new Error(
            "No se encontró una sesión válida."
          );

        }


        const headers = {

          Authorization:
            `Bearer ${token}`

        };


        const [
          respuestaPerfil,
          respuestaAreas
        ] =
          await Promise.all([

            fetch(
              `${API_URL}/api/psicologos/mi-perfil`,
              {
                headers
              }
            ),

            fetch(
              `${API_URL}/api/psicologos/areas-atencion`,
              {
                headers
              }
            )

          ]);


        const dataPerfil =
          await respuestaPerfil
            .json()
            .catch(
              () => ({})
            );


        const dataAreas =
          await respuestaAreas
            .json()
            .catch(
              () => ({})
            );


        if (
          !respuestaPerfil.ok
        ) {

          throw new Error(
            dataPerfil?.message ||
            "No fue posible cargar el perfil profesional."
          );

        }


        if (
          !respuestaAreas.ok
        ) {

          throw new Error(
            dataAreas?.message ||
            "No fue posible cargar las áreas de atención."
          );

        }


        cargarDatosPerfil(
          dataPerfil?.perfil ||
          {}
        );


        setAreas(
          Array.isArray(
            dataAreas?.areas
          )
            ? dataAreas.areas
            : []
        );


        const cp =
          String(
            dataPerfil
              ?.perfil
              ?.codigo_postal ||
            ""
          ).trim();


        if (
          /^\d{5}$/.test(cp)
        ) {

          await buscarCodigoPostal(
            cp,
            false
          );

        }


      } catch (err) {

        console.error(
          "❌ Error cargando perfil profesional:",
          err
        );


        setError(
          err?.message ||
          "No fue posible cargar el perfil profesional."
        );


      } finally {

        setCargando(false);

      }

    };


  useEffect(
    () => {

      cargarInformacion();

      // eslint-disable-next-line react-hooks/exhaustive-deps
    },
    []
  );


  // ==================================================
  // CAMBIAR CAMPO
  // ==================================================

  const cambiarCampo =
    e => {

      const {
        name,
        value,
        type,
        checked
      } =
        e.target;


      setForm(
        actual => ({

          ...actual,

          [name]:
            type ===
            "checkbox"
              ? checked
              : value

        })
      );


      setError("");
      setMensaje("");

    };


  // ==================================================
  // ÁREAS DE ATENCIÓN
  // ==================================================

  const cambiarArea =
    idArea => {

      const id =
        Number(
          idArea
        );


      setForm(
        actual => {

          const seleccionadas =
            actual
              .areas_atencion ||
            [];


          const existe =
            seleccionadas
              .includes(
                id
              );


          return {

            ...actual,

            areas_atencion:
              existe
                ? seleccionadas
                    .filter(
                      item =>
                        item !== id
                    )
                : [
                    ...seleccionadas,
                    id
                  ]

          };

        }
      );


      setError("");
      setMensaje("");

    };


  // ==================================================
  // NORMALIZAR RESPUESTA POSTALI
  // ==================================================

  const normalizarColonias =
    data => {

      const posibles = [

        data?.colonias,

        data?.data?.colonias,

        data?.settlements,

        data?.data?.settlements,

        data?.resultado?.colonias

      ];


      for (
        const lista
        of posibles
      ) {

        if (
          Array.isArray(
            lista
          )
        ) {

          return lista
            .map(
              item => {

                if (
                  typeof item ===
                  "string"
                ) {

                  return item;

                }


                return (
                  item?.nombre ||
                  item?.name ||
                  item?.colonia ||
                  item?.settlement ||
                  ""
                );

              }
            )
            .filter(
              Boolean
            );

        }

      }


      return [];

    };


  // ==================================================
  // BUSCAR CÓDIGO POSTAL
  // ==================================================

  const buscarCodigoPostal =
    async (
      cpRecibido = null,
      mostrarErrores = true
    ) => {

      const cp =
        String(
          cpRecibido ??
          form.codigo_postal ??
          ""
        )
          .replace(
            /\D/g,
            ""
          )
          .slice(
            0,
            5
          );


      if (
        cp.length !== 5
      ) {

        if (
          mostrarErrores
        ) {

          setError(
            "El código postal debe contener 5 dígitos."
          );

        }

        return;

      }


      try {

        setBuscandoCP(true);


        if (
          mostrarErrores
        ) {

          setError("");

        }


        const respuesta =
          await fetch(
            `${API_URL}/api/codigos-postales/${cp}`,
            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }
          );


        const data =
          await respuesta
            .json()
            .catch(
              () => ({})
            );


        if (
          !respuesta.ok
        ) {

          throw new Error(
            data?.message ||
            "No fue posible consultar el código postal."
          );

        }


        const listaColonias =
          normalizarColonias(
            data
          );


        setColonias(
          listaColonias
        );


        const estado =
          data?.estado ||
          data?.state ||
          data?.data?.estado ||
          data?.data?.state ||
          data?.entidad ||
          data?.data?.entidad ||
          "";


        const municipio =
          data?.municipio ||
          data?.municipality ||
          data?.data?.municipio ||
          data?.data?.municipality ||
          data?.alcaldia ||
          data?.data?.alcaldia ||
          "";


        setForm(
          actual => ({

            ...actual,

            codigo_postal:
              cp,

            estado:
              estado ||
              actual.estado,

            municipio:
              municipio ||
              actual.municipio,

            colonia:
              listaColonias.includes(
                actual.colonia
              )
                ? actual.colonia
                : ""

          })
        );


      } catch (err) {

        console.error(
          "❌ Error consultando código postal:",
          err
        );


        setColonias([]);


        if (
          mostrarErrores
        ) {

          setError(
            err?.message ||
            "No fue posible consultar el código postal."
          );

        }


      } finally {

        setBuscandoCP(false);

      }

    };


  // ==================================================
  // CAMBIAR CP
  // ==================================================

  const cambiarCodigoPostal =
    e => {

      const cp =
        String(
          e.target.value ||
          ""
        )
          .replace(
            /\D/g,
            ""
          )
          .slice(
            0,
            5
          );


      setForm(
        actual => ({

          ...actual,

          codigo_postal:
            cp,

          estado:
            cp.length === 5
              ? actual.estado
              : "",

          municipio:
            cp.length === 5
              ? actual.municipio
              : "",

          colonia:
            cp.length === 5
              ? actual.colonia
              : ""

        })
      );


      if (
        cp.length < 5
      ) {

        setColonias([]);

      }


      if (
        cp.length === 5
      ) {

        buscarCodigoPostal(
          cp
        );

      }

    };


  // ==================================================
  // SUBIR FOTO PROFESIONAL
  // ==================================================

  const subirFoto =
    async e => {

      const input =
        e.target;


      const archivo =
        input.files?.[0];


      if (
        !archivo
      ) {
        return;
      }


      const tiposPermitidos = [

        "image/jpeg",
        "image/jpg",
        "image/png",
        "image/webp"

      ];


      if (
        !tiposPermitidos
          .includes(
            archivo.type
          )
      ) {

        setError(
          "Selecciona una imagen JPG, PNG o WEBP."
        );


        input.value =
          "";

        return;

      }


      if (
        archivo.size >
        5 * 1024 * 1024
      ) {

        setError(
          "La imagen no puede pesar más de 5 MB."
        );


        input.value =
          "";

        return;

      }


      try {

        setSubiendoFoto(
          true
        );

        setError("");
        setMensaje("");


        const formData =
          new FormData();


        formData.append(
          "foto",
          archivo
        );


        const respuesta =
          await fetch(
            `${API_URL}/api/psicologos/mi-perfil/foto`,
            {

              method:
                "POST",

              headers: {

                Authorization:
                  `Bearer ${token}`

              },

              body:
                formData

            }
          );


        const data =
          await respuesta
            .json()
            .catch(
              () => ({})
            );


        if (
          !respuesta.ok
        ) {

          throw new Error(
            data?.message ||
            "No fue posible subir la foto."
          );

        }


        setForm(
          actual => ({

            ...actual,

            foto_url:
              data?.foto_url ||
              ""

          })
        );


        setMensaje(
          data?.message ||
          "Foto profesional actualizada correctamente."
        );


      } catch (err) {

        console.error(
          "❌ Error subiendo foto:",
          err
        );


        setError(
          err?.message ||
          "No fue posible subir la foto."
        );


      } finally {

        setSubiendoFoto(
          false
        );


        input.value =
          "";

      }

    };


  // ==================================================
  // VALIDACIONES VISUALES
  // ==================================================

  const requisitos =
    useMemo(
      () => {

        const tieneDatos =
          Boolean(
            String(
              form
                .cedula_profesional ||
              ""
            ).trim()
          ) &&
          Boolean(
            String(
              form.especialidad ||
              ""
            ).trim()
          ) &&
          form
            .anos_experiencia !==
            "" &&
          Boolean(
            String(
              form
                .descripcion_profesional ||
              ""
            ).trim()
          );


        const tieneAreas =
          Array.isArray(
            form.areas_atencion
          ) &&
          form
            .areas_atencion
            .length > 0;


        const tieneModalidad =
          form
            .modalidad_presencial ||
          form
            .modalidad_videollamada;


        const precioPresencialOk =
          !form
            .modalidad_presencial ||
          Number(
            form
              .precio_presencial
          ) > 0;


        const ubicacionOk =
          !form
            .modalidad_presencial ||
          (
            /^\d{5}$/.test(
              String(
                form
                  .codigo_postal ||
                ""
              )
            ) &&
            Boolean(
              form.estado
            ) &&
            Boolean(
              form.municipio
            ) &&
            Boolean(
              form.colonia
            ) &&
            Boolean(
              String(
                form
                  .direccion_consultorio ||
                ""
              ).trim()
            )
          );


        const precioVideoOk =
          !form
            .modalidad_videollamada ||
          Number(
            form
              .precio_videollamada
          ) > 0;


        const disponibilidadOk =
          Boolean(
            String(
              form.disponibilidad ||
              ""
            ).trim()
          );


        return [

          {
            texto:
              "Cédula profesional",
            completo:
              Boolean(
                String(
                  form
                    .cedula_profesional ||
                  ""
                ).trim()
              )
          },

          {
            texto:
              "Especialidad principal",
            completo:
              Boolean(
                String(
                  form.especialidad ||
                  ""
                ).trim()
              )
          },

          {
            texto:
              "Experiencia y descripción",
            completo:
              tieneDatos
          },

          {
            texto:
              "Áreas de atención",
            completo:
              tieneAreas
          },

          {
            texto:
              "Modalidad de atención",
            completo:
              tieneModalidad
          },

          {
            texto:
              "Honorarios",
            completo:
              precioPresencialOk &&
              precioVideoOk
          },

          {
            texto:
              "Ubicación del consultorio",
            completo:
              ubicacionOk
          },

          {
            texto:
              "Disponibilidad",
            completo:
              disponibilidadOk
          },

          {
            texto:
              "Datos necesarios para canalización",
            completo:
              tieneDatos &&
              tieneAreas &&
              tieneModalidad &&
              precioPresencialOk &&
              precioVideoOk &&
              ubicacionOk &&
              disponibilidadOk
          }

        ];

      },
      [
        form
      ]
    );


  const porcentaje =
    useMemo(
      () => {

        const completos =
          requisitos
            .filter(
              item =>
                item.completo
            )
            .length;


        return Math.round(
          (
            completos /
            requisitos.length
          ) *
          100
        );

      },
      [
        requisitos
      ]
    );


  // ==================================================
  // GUARDAR PERFIL
  // ==================================================

  const guardarPerfil =
    async e => {

      e.preventDefault();


      try {

        setGuardando(true);

        setError("");
        setMensaje("");


        const payload = {

          cedula_profesional:
            form
              .cedula_profesional
              .trim(),

          especialidad:
            form
              .especialidad
              .trim(),

          // Conservamos foto_url que ya fue
          // guardada por la subida independiente.
          foto_url:
            form.foto_url ||
            null,

          descripcion_profesional:
            form
              .descripcion_profesional
              .trim(),

          anos_experiencia:
            form
              .anos_experiencia ===
              ""
                ? null
                : Number(
                    form
                      .anos_experiencia
                  ),

          areas_atencion:
            form
              .areas_atencion,

          modalidad_presencial:
            form
              .modalidad_presencial,

          modalidad_videollamada:
            form
              .modalidad_videollamada,

          precio_presencial:
            form
              .modalidad_presencial
                ? (
                    form
                      .precio_presencial ===
                    ""
                      ? null
                      : Number(
                          form
                            .precio_presencial
                        )
                  )
                : null,

          precio_videollamada:
            form
              .modalidad_videollamada
                ? (
                    form
                      .precio_videollamada ===
                    ""
                      ? null
                      : Number(
                          form
                            .precio_videollamada
                        )
                  )
                : null,

          estado:
            form
              .modalidad_presencial
                ? form.estado
                : null,

          municipio:
            form
              .modalidad_presencial
                ? form.municipio
                : null,

          colonia:
            form
              .modalidad_presencial
                ? form.colonia
                : null,

          codigo_postal:
            form
              .modalidad_presencial
                ? form.codigo_postal
                : null,

          direccion_consultorio:
            form
              .modalidad_presencial
                ? form
                    .direccion_consultorio
                    .trim()
                : null,

          disponibilidad:
            form
              .disponibilidad
              .trim(),

          activo_canalizacion:
            Boolean(
              form
                .activo_canalizacion
            )

        };


        const respuesta =
          await fetch(
            `${API_URL}/api/psicologos/mi-perfil`,
            {

              method:
                "PUT",

              headers: {

                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${token}`

              },

              body:
                JSON.stringify(
                  payload
                )

            }
          );


        const data =
          await respuesta
            .json()
            .catch(
              () => ({})
            );


        if (
          !respuesta.ok
        ) {

          throw new Error(
            data?.message ||
            "No fue posible guardar el perfil profesional."
          );

        }


        if (
          data?.perfil
        ) {

          cargarDatosPerfil(
            data.perfil
          );

        }


        setMensaje(
          data?.message ||
          "Perfil profesional actualizado correctamente."
        );


        window.scrollTo({
          top: 0,
          behavior:
            "smooth"
        });


      } catch (err) {

        console.error(
          "❌ Error guardando perfil:",
          err
        );


        setError(
          err?.message ||
          "No fue posible guardar el perfil profesional."
        );


      } finally {

        setGuardando(false);

      }

    };


  // ==================================================
  // CARGANDO
  // ==================================================

  if (
    cargando
  ) {

    return (

      <div style={styles.page}>

        <div style={styles.container}>

          <div style={styles.loadingCard}>

            <div style={styles.loadingIcon}>
              🪪
            </div>

            <h2>
              Perfil profesional
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
  // RENDER
  // ==================================================

  return (

    <div style={styles.page}>

      <div style={styles.container}>

        {/* ============================================
            ENCABEZADO
        ============================================ */}

        <div style={styles.header}>

          <div>

            <button
              type="button"
              style={styles.backButton}
              onClick={
                () =>
                  navigate(
                    "/dashboard"
                  )
              }
            >
              ← Volver al dashboard
            </button>


            <h1 style={styles.title}>
              🪪 Mi perfil profesional
            </h1>


            <p style={styles.subtitle}>
              Completa tu información profesional para
              aparecer como opción de atención en las
              canalizaciones de Recursos Humanos.
            </p>

          </div>

        </div>


        {/* ============================================
            PROGRESO
        ============================================ */}

        <div style={styles.progressCard}>

          <div style={styles.progressTop}>

            <div>

              <div style={styles.progressLabel}>
                Perfil profesional
              </div>

              <div style={styles.progressValue}>
                {porcentaje}%
              </div>

            </div>


            <div
              style={{
                ...styles.statusBadge,

                ...(form
                  .perfil_profesional_completo
                  ? styles.statusComplete
                  : styles.statusPending)
              }}
            >

              {form
                .perfil_profesional_completo
                  ? "✓ Perfil completo"
                  : "Perfil pendiente"}

            </div>

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

        </div>


        {/* ============================================
            MENSAJES
        ============================================ */}

        {error && (

          <div style={styles.errorBox}>
            ⚠️ {error}
          </div>

        )}


        {mensaje && (

          <div style={styles.successBox}>
            ✅ {mensaje}
          </div>

        )}


        {/* ============================================
            FORMULARIO
        ============================================ */}

        <form
          onSubmit={
            guardarPerfil
          }
        >

          {/* ==========================================
              DATOS PROFESIONALES
          ========================================== */}

          <section style={styles.card}>

            <div style={styles.sectionHeader}>

              <div style={styles.sectionIcon}>
                👩‍⚕️
              </div>

              <div>

                <h2 style={styles.sectionTitle}>
                  Datos profesionales
                </h2>

                <p style={styles.sectionDescription}>
                  Información que podrá utilizarse para
                  presentar tu perfil profesional.
                </p>

              </div>

            </div>


            <div style={styles.gridTwo}>

              <Field
                label="Nombre"
              >

                <input
                  style={{
                    ...styles.input,
                    ...styles.disabledInput
                  }}
                  value={
                    form.nombre
                  }
                  disabled
                />

              </Field>


              <Field
                label="Correo electrónico"
              >

                <input
                  style={{
                    ...styles.input,
                    ...styles.disabledInput
                  }}
                  value={
                    form.correo
                  }
                  disabled
                />

              </Field>


              <Field
                label="Cédula profesional"
                required
              >

                <input
                  style={styles.input}
                  name="cedula_profesional"
                  value={
                    form
                      .cedula_profesional
                  }
                  onChange={
                    cambiarCampo
                  }
                  placeholder="Ej. 12345678"
                />

              </Field>


              <Field
                label="Especialidad principal"
                required
              >

                <input
                  style={styles.input}
                  name="especialidad"
                  value={
                    form.especialidad
                  }
                  onChange={
                    cambiarCampo
                  }
                  placeholder="Ej. Psicología clínica"
                />

              </Field>


              <Field
                label="Años de experiencia"
                required
              >

                <input
                  type="number"
                  min="0"
                  max="80"
                  style={styles.input}
                  name="anos_experiencia"
                  value={
                    form
                      .anos_experiencia
                  }
                  onChange={
                    cambiarCampo
                  }
                  placeholder="Ej. 5"
                />

              </Field>


              {/* ======================================
                  FOTO PROFESIONAL
              ====================================== */}

              <Field
                label="Foto profesional"
              >

                <div style={styles.photoSection}>

                  <div style={styles.photoPreview}>

                    {form.foto_url ? (

                      <img
                        key={
                          form.foto_url
                        }
                        src={
                          obtenerUrlFoto(
                            form.foto_url
                          )
                        }
                        alt="Foto profesional"
                        style={styles.photoImage}
                      />

                    ) : (

                      <div style={styles.photoPlaceholder}>
                        👤
                      </div>

                    )}

                  </div>


                  <div style={styles.photoActions}>

                    <label
                      style={{
                        ...styles.uploadPhotoButton,

                        ...(subiendoFoto
                          ? styles.disabledUploadButton
                          : {})
                      }}
                    >

                      {subiendoFoto
                        ? "Subiendo..."
                        : form.foto_url
                        ? "📷 Cambiar foto"
                        : "📷 Seleccionar foto"}


                      <input
                        type="file"
                        accept="image/jpeg,image/png,image/webp"
                        onChange={
                          subirFoto
                        }
                        disabled={
                          subiendoFoto
                        }
                        style={{
                          display:
                            "none"
                        }}
                      />

                    </label>


                    <span style={styles.photoHelp}>
                      JPG, PNG o WEBP · Máximo 5 MB
                    </span>

                  </div>

                </div>

              </Field>

            </div>


            <Field
              label="Descripción profesional"
              required
            >

              <textarea
                style={styles.textarea}
                name="descripcion_profesional"
                value={
                  form
                    .descripcion_profesional
                }
                onChange={
                  cambiarCampo
                }
                rows={5}
                placeholder="Describe brevemente tu experiencia, enfoque profesional y tipo de atención que brindas."
              />

            </Field>

          </section>


          {/* ==========================================
              ÁREAS DE ATENCIÓN
          ========================================== */}

          <section style={styles.card}>

            <div style={styles.sectionHeader}>

              <div style={styles.sectionIcon}>
                🧠
              </div>

              <div>

                <h2 style={styles.sectionTitle}>
                  Áreas de atención
                </h2>

                <p style={styles.sectionDescription}>
                  Selecciona las áreas en las que tienes
                  experiencia profesional.
                </p>

              </div>

            </div>


            <div style={styles.areasGrid}>

              {areas.map(
                area => {

                  const id =
                    Number(
                      area.id_area
                    );


                  const seleccionado =
                    form
                      .areas_atencion
                      .includes(
                        id
                      );


                  return (

                    <button
                      key={
                        area.id_area
                      }
                      type="button"
                      onClick={
                        () =>
                          cambiarArea(
                            id
                          )
                      }
                      style={{
                        ...styles.areaButton,

                        ...(seleccionado
                          ? styles.areaButtonSelected
                          : {})
                      }}
                    >

                      <span>
                        {seleccionado
                          ? "✓ "
                          : ""}
                      </span>

                      {area.nombre}

                    </button>

                  );

                }
              )}

            </div>

          </section>


          {/* ==========================================
              MODALIDAD
          ========================================== */}

          <section style={styles.card}>

            <div style={styles.sectionHeader}>

              <div style={styles.sectionIcon}>
                💬
              </div>

              <div>

                <h2 style={styles.sectionTitle}>
                  Modalidad de atención
                </h2>

                <p style={styles.sectionDescription}>
                  Indica cómo puedes brindar atención
                  psicológica.
                </p>

              </div>

            </div>


            <div style={styles.modalityGrid}>

              <label
                style={{
                  ...styles.modalityCard,

                  ...(form
                    .modalidad_presencial
                    ? styles.modalitySelected
                    : {})
                }}
              >

                <input
                  type="checkbox"
                  name="modalidad_presencial"
                  checked={
                    form
                      .modalidad_presencial
                  }
                  onChange={
                    cambiarCampo
                  }
                />

                <div>

                  <strong>
                    🏢 Presencial
                  </strong>

                  <p style={styles.smallText}>
                    Atención en consultorio.
                  </p>

                </div>

              </label>


              <label
                style={{
                  ...styles.modalityCard,

                  ...(form
                    .modalidad_videollamada
                    ? styles.modalitySelected
                    : {})
                }}
              >

                <input
                  type="checkbox"
                  name="modalidad_videollamada"
                  checked={
                    form
                      .modalidad_videollamada
                  }
                  onChange={
                    cambiarCampo
                  }
                />

                <div>

                  <strong>
                    💻 Videollamada
                  </strong>

                  <p style={styles.smallText}>
                    Atención psicológica en línea.
                  </p>

                </div>

              </label>

            </div>

          </section>


          {/* ==========================================
              HONORARIOS
          ========================================== */}

          <section style={styles.card}>

            <div style={styles.sectionHeader}>

              <div style={styles.sectionIcon}>
                💰
              </div>

              <div>

                <h2 style={styles.sectionTitle}>
                  Honorarios
                </h2>

                <p style={styles.sectionDescription}>
                  Indica el costo por sesión de cada
                  modalidad que ofreces.
                </p>

              </div>

            </div>


            <div style={styles.gridTwo}>

              {form
                .modalidad_presencial && (

                <Field
                  label="Costo de sesión presencial"
                  required
                >

                  <div style={styles.moneyInput}>

                    <span style={styles.moneySymbol}>
                      $
                    </span>

                    <input
                      type="number"
                      min="0"
                      step="0.01"
                      style={styles.moneyField}
                      name="precio_presencial"
                      value={
                        form
                          .precio_presencial
                      }
                      onChange={
                        cambiarCampo
                      }
                      placeholder="Ej. 600"
                    />

                    <span style={styles.moneyCurrency}>
                      MXN
                    </span>

                  </div>

                </Field>

              )}


              {form
                .modalidad_videollamada && (

                <Field
                  label="Costo de sesión por videollamada"
                  required
                >

                  <div style={styles.moneyInput}>

                    <span style={styles.moneySymbol}>
                      $
                    </span>

                    <input
                      type="number"
                      min="0"
                      step="0.01"
                      style={styles.moneyField}
                      name="precio_videollamada"
                      value={
                        form
                          .precio_videollamada
                      }
                      onChange={
                        cambiarCampo
                      }
                      placeholder="Ej. 500"
                    />

                    <span style={styles.moneyCurrency}>
                      MXN
                    </span>

                  </div>

                </Field>

              )}

            </div>

          </section>


          {/* ==========================================
              UBICACIÓN
          ========================================== */}

          {form
            .modalidad_presencial && (

            <section style={styles.card}>

              <div style={styles.sectionHeader}>

                <div style={styles.sectionIcon}>
                  📍
                </div>

                <div>

                  <h2 style={styles.sectionTitle}>
                    Ubicación del consultorio
                  </h2>

                  <p style={styles.sectionDescription}>
                    Esta información permitirá considerar
                    la cercanía en las canalizaciones.
                  </p>

                </div>

              </div>


              <div style={styles.gridTwo}>

                <Field
                  label="Código postal"
                  required
                >

                  <div style={styles.cpRow}>

                    <input
                      style={styles.input}
                      value={
                        form
                          .codigo_postal
                      }
                      onChange={
                        cambiarCodigoPostal
                      }
                      inputMode="numeric"
                      maxLength={5}
                      placeholder="Ej. 56400"
                    />


                    <button
                      type="button"
                      style={styles.cpButton}
                      onClick={
                        () =>
                          buscarCodigoPostal()
                      }
                      disabled={
                        buscandoCP
                      }
                    >

                      {buscandoCP
                        ? "Buscando..."
                        : "Buscar"}

                    </button>

                  </div>

                </Field>


                <Field
                  label="Estado"
                  required
                >

                  <input
                    style={{
                      ...styles.input,
                      ...styles.disabledInput
                    }}
                    name="estado"
                    value={
                      form.estado
                    }
                    readOnly
                    placeholder="Estado"
                  />

                </Field>


                <Field
                  label="Municipio / alcaldía"
                  required
                >

                  <input
                    style={{
                      ...styles.input,
                      ...styles.disabledInput
                    }}
                    name="municipio"
                    value={
                      form.municipio
                    }
                    readOnly
                    placeholder="Municipio"
                  />

                </Field>


                <Field
                  label="Colonia"
                  required
                >

                  {colonias.length > 0 ? (

                    <select
                      style={styles.input}
                      name="colonia"
                      value={
                        form.colonia
                      }
                      onChange={
                        cambiarCampo
                      }
                    >

                      <option value="">
                        Selecciona una colonia
                      </option>

                      {colonias.map(
                        colonia => (

                          <option
                            key={
                              colonia
                            }
                            value={
                              colonia
                            }
                          >
                            {colonia}
                          </option>

                        )
                      )}

                    </select>

                  ) : (

                    <input
                      style={styles.input}
                      name="colonia"
                      value={
                        form.colonia
                      }
                      onChange={
                        cambiarCampo
                      }
                      placeholder="Colonia"
                    />

                  )}

                </Field>

              </div>


              <Field
                label="Dirección del consultorio"
                required
              >

                <input
                  style={styles.input}
                  name="direccion_consultorio"
                  value={
                    form
                      .direccion_consultorio
                  }
                  onChange={
                    cambiarCampo
                  }
                  placeholder="Calle, número, interior y referencias necesarias"
                />

              </Field>

            </section>

          )}


          {/* ==========================================
              DISPONIBILIDAD
          ========================================== */}

          <section style={styles.card}>

            <div style={styles.sectionHeader}>

              <div style={styles.sectionIcon}>
                📅
              </div>

              <div>

                <h2 style={styles.sectionTitle}>
                  Disponibilidad
                </h2>

                <p style={styles.sectionDescription}>
                  Describe de forma general tus horarios
                  disponibles.
                </p>

              </div>

            </div>


            <Field
              label="Horarios disponibles"
              required
            >

              <textarea
                style={styles.textarea}
                name="disponibilidad"
                value={
                  form.disponibilidad
                }
                onChange={
                  cambiarCampo
                }
                rows={4}
                placeholder="Ej. Lunes a viernes de 16:00 a 20:00 y sábados de 9:00 a 13:00."
              />

            </Field>

          </section>


          {/* ==========================================
              ESTADO PARA CANALIZACIONES
          ========================================== */}

          <section style={styles.card}>

            <div style={styles.sectionHeader}>

              <div style={styles.sectionIcon}>
                🔗
              </div>

              <div>

                <h2 style={styles.sectionTitle}>
                  Canalizaciones de RH
                </h2>

                <p style={styles.sectionDescription}>
                  Cuando tu perfil esté completo podrás
                  indicar si deseas aparecer como opción
                  disponible.
                </p>

              </div>

            </div>


            <label
              style={{
                ...styles.activationCard,

                ...(Boolean(
                  form
                    .activo_canalizacion
                )
                  ? styles.activationActive
                  : {})
              }}
            >

              <input
                type="checkbox"
                name="activo_canalizacion"
                checked={
                  Boolean(
                    form
                      .activo_canalizacion
                  )
                }
                onChange={
                  cambiarCampo
                }
                disabled={
                  !form
                    .perfil_profesional_completo &&
                  porcentaje < 100
                }
              />


              <div>

                <strong>
                  Disponible para canalizaciones
                </strong>

                <p style={styles.smallText}>

                  {form
                    .perfil_profesional_completo ||
                  porcentaje === 100
                    ? "Puedes activar o desactivar tu disponibilidad."
                    : "Completa primero todos los datos obligatorios."}

                </p>

              </div>

            </label>

          </section>


          {/* ==========================================
              REQUISITOS
          ========================================== */}

          <section style={styles.card}>

            <div style={styles.sectionHeader}>

              <div style={styles.sectionIcon}>
                ✅
              </div>

              <div>

                <h2 style={styles.sectionTitle}>
                  Requisitos del perfil
                </h2>

                <p style={styles.sectionDescription}>
                  Revisa qué información falta para
                  completar tu perfil profesional.
                </p>

              </div>

            </div>


            <div style={styles.requirementsGrid}>

              {requisitos.map(
                requisito => (

                  <div
                    key={
                      requisito.texto
                    }
                    style={{
                      ...styles.requirement,

                      ...(requisito.completo
                        ? styles.requirementComplete
                        : {})
                    }}
                  >

                    <span style={styles.requirementIcon}>

                      {requisito.completo
                        ? "✓"
                        : "○"}

                    </span>

                    {requisito.texto}

                  </div>

                )
              )}

            </div>

          </section>


          {/* ==========================================
              BOTONES
          ========================================== */}

          <div style={styles.actions}>

            <button
              type="button"
              style={styles.secondaryButton}
              onClick={
                () =>
                  navigate(
                    "/dashboard"
                  )
              }
              disabled={
                guardando
              }
            >
              Cancelar
            </button>


            <button
              type="submit"
              style={{
                ...styles.primaryButton,

                ...(guardando
                  ? styles.disabledButton
                  : {})
              }}
              disabled={
                guardando
              }
            >

              {guardando
                ? "Guardando..."
                : "💾 Guardar perfil profesional"}

            </button>

          </div>

        </form>

      </div>

    </div>

  );

}


// ==================================================
// ESTILOS
// ==================================================

const styles = {

  page: {

    minHeight:
      "100vh",

    background:
      "#F3F6FA",

    padding:
      "32px 18px 60px",

    fontFamily:
      "Inter, Arial, sans-serif",

    color:
      "#243B5A"

  },


  container: {

    width:
      "100%",

    maxWidth:
      "1180px",

    margin:
      "0 auto"

  },


  header: {

    marginBottom:
      "22px"

  },


  backButton: {

    border:
      "none",

    background:
      "transparent",

    color:
      "#5B6F8B",

    cursor:
      "pointer",

    fontSize:
      "14px",

    fontWeight:
      "700",

    padding:
      "0",

    marginBottom:
      "12px"

  },


  title: {

    margin:
      "0 0 8px",

    fontSize:
      "30px",

    color:
      "#263F65"

  },


  subtitle: {

    margin:
      0,

    lineHeight:
      1.6,

    color:
      "#6D7F96",

    maxWidth:
      "850px"

  },


  progressCard: {

    background:
      "#FFFFFF",

    borderRadius:
      "18px",

    padding:
      "22px",

    marginBottom:
      "20px",

    boxShadow:
      "0 8px 30px rgba(35,61,94,.08)",

    border:
      "1px solid #E5ECF5"

  },


  progressTop: {

    display:
      "flex",

    justifyContent:
      "space-between",

    alignItems:
      "center",

    gap:
      "15px",

    flexWrap:
      "wrap",

    marginBottom:
      "15px"

  },


  progressLabel: {

    color:
      "#6D7F96",

    fontWeight:
      "700",

    fontSize:
      "14px"

  },


  progressValue: {

    color:
      "#6848D3",

    fontWeight:
      "800",

    fontSize:
      "28px",

    marginTop:
      "2px"

  },


  statusBadge: {

    padding:
      "8px 13px",

    borderRadius:
      "999px",

    fontSize:
      "13px",

    fontWeight:
      "800"

  },


  statusComplete: {

    background:
      "#E8F8EF",

    color:
      "#23824C"

  },


  statusPending: {

    background:
      "#FFF4E3",

    color:
      "#A46711"

  },


  progressTrack: {

    width:
      "100%",

    height:
      "10px",

    borderRadius:
      "999px",

    overflow:
      "hidden",

    background:
      "#E9EEF5"

  },


  progressBar: {

    height:
      "100%",

    borderRadius:
      "999px",

    background:
      "linear-gradient(90deg,#6848D3,#8F74E8)",

    transition:
      "width .25s ease"

  },


  errorBox: {

    background:
      "#FFF1F1",

    color:
      "#B42318",

    border:
      "1px solid #FFD1D1",

    borderRadius:
      "12px",

    padding:
      "14px 17px",

    marginBottom:
      "18px",

    fontWeight:
      "600"

  },


  successBox: {

    background:
      "#ECF9F1",

    color:
      "#287A4B",

    border:
      "1px solid #CBEBD8",

    borderRadius:
      "12px",

    padding:
      "14px 17px",

    marginBottom:
      "18px",

    fontWeight:
      "600"

  },


  card: {

    background:
      "#FFFFFF",

    borderRadius:
      "18px",

    padding:
      "26px",

    marginBottom:
      "20px",

    boxShadow:
      "0 8px 30px rgba(35,61,94,.07)",

    border:
      "1px solid #E5ECF5"

  },


  sectionHeader: {

    display:
      "flex",

    alignItems:
      "flex-start",

    gap:
      "14px",

    marginBottom:
      "24px"

  },


  sectionIcon: {

    width:
      "44px",

    height:
      "44px",

    borderRadius:
      "12px",

    background:
      "#F0ECFF",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    fontSize:
      "22px",

    flexShrink:
      0

  },


  sectionTitle: {

    margin:
      "0 0 4px",

    color:
      "#29476F",

    fontSize:
      "20px"

  },


  sectionDescription: {

    margin:
      0,

    color:
      "#7B8CA3",

    fontSize:
      "14px",

    lineHeight:
      1.5

  },


  gridTwo: {

    display:
      "grid",

    gridTemplateColumns:
      "repeat(auto-fit,minmax(280px,1fr))",

    gap:
      "18px"

  },


  field: {

    display:
      "flex",

    flexDirection:
      "column",

    gap:
      "8px",

    marginBottom:
      "18px",

    minWidth:
      0

  },


  label: {

    color:
      "#2E4E78",

    fontSize:
      "14px",

    fontWeight:
      "700"

  },


  required: {

    color:
      "#D34B4B"

  },


  input: {

    width:
      "100%",

    minHeight:
      "52px",

    boxSizing:
      "border-box",

    border:
      "1px solid #CBD8E8",

    borderRadius:
      "12px",

    padding:
      "0 15px",

    outline:
      "none",

    fontSize:
      "15px",

    color:
      "#344D6C",

    background:
      "#FFFFFF"

  },


  disabledInput: {

    background:
      "#F5F7FA",

    color:
      "#788AA1"

  },


  textarea: {

    width:
      "100%",

    boxSizing:
      "border-box",

    border:
      "1px solid #CBD8E8",

    borderRadius:
      "12px",

    padding:
      "15px",

    resize:
      "vertical",

    outline:
      "none",

    fontSize:
      "15px",

    lineHeight:
      1.6,

    fontFamily:
      "inherit",

    color:
      "#344D6C"

  },


  photoSection: {

    display:
      "flex",

    alignItems:
      "center",

    gap:
      "18px",

    flexWrap:
      "wrap",

    minHeight:
      "110px"

  },


  photoPreview: {

    width:
      "105px",

    height:
      "105px",

    borderRadius:
      "50%",

    overflow:
      "hidden",

    border:
      "4px solid #EEF2F8",

    background:
      "#F4F1FF",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    flexShrink:
      0,

    boxShadow:
      "0 5px 18px rgba(43,76,116,.10)"

  },


  photoImage: {

    width:
      "100%",

    height:
      "100%",

    objectFit:
      "cover",

    display:
      "block"

  },


  photoPlaceholder: {

    width:
      "100%",

    height:
      "100%",

    display:
      "flex",

    justifyContent:
      "center",

    alignItems:
      "center",

    fontSize:
      "44px"

  },


  photoActions: {

    display:
      "flex",

    flexDirection:
      "column",

    alignItems:
      "flex-start",

    gap:
      "8px"

  },


  uploadPhotoButton: {

    display:
      "inline-flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    minHeight:
      "43px",

    padding:
      "0 18px",

    borderRadius:
      "10px",

    background:
      "#6848D3",

    color:
      "#FFFFFF",

    fontWeight:
      "800",

    fontSize:
      "14px",

    cursor:
      "pointer",

    boxShadow:
      "0 5px 14px rgba(104,72,211,.20)"

  },


  disabledUploadButton: {

    opacity:
      0.6,

    cursor:
      "not-allowed"

  },


  photoHelp: {

    color:
      "#8190A3",

    fontSize:
      "12px"

  },


  areasGrid: {

    display:
      "flex",

    flexWrap:
      "wrap",

    gap:
      "10px"

  },


  areaButton: {

    padding:
      "10px 14px",

    borderRadius:
      "999px",

    background:
      "#F6F8FB",

    color:
      "#52677F",

    border:
      "1px solid #DCE5EF",

    cursor:
      "pointer",

    fontWeight:
      "700",

    fontSize:
      "13px"

  },


  areaButtonSelected: {

    background:
      "#EEE9FF",

    border:
      "1px solid #8B72E3",

    color:
      "#5B3FC0"

  },


  modalityGrid: {

    display:
      "grid",

    gridTemplateColumns:
      "repeat(auto-fit,minmax(260px,1fr))",

    gap:
      "15px"

  },


  modalityCard: {

    display:
      "flex",

    alignItems:
      "flex-start",

    gap:
      "12px",

    border:
      "1px solid #D9E3EF",

    borderRadius:
      "14px",

    padding:
      "18px",

    cursor:
      "pointer",

    background:
      "#FFFFFF"

  },


  modalitySelected: {

    border:
      "1px solid #8065DF",

    background:
      "#F4F1FF"

  },


  smallText: {

    margin:
      "5px 0 0",

    color:
      "#77889D",

    fontSize:
      "13px",

    lineHeight:
      1.4

  },


  moneyInput: {

    display:
      "flex",

    alignItems:
      "center",

    border:
      "1px solid #CBD8E8",

    borderRadius:
      "12px",

    overflow:
      "hidden",

    minHeight:
      "52px"

  },


  moneySymbol: {

    padding:
      "0 12px",

    color:
      "#647890",

    fontWeight:
      "800"

  },


  moneyField: {

    flex:
      1,

    height:
      "50px",

    border:
      "none",

    outline:
      "none",

    fontSize:
      "15px",

    minWidth:
      0

  },


  moneyCurrency: {

    padding:
      "0 13px",

    color:
      "#7C8DA1",

    fontSize:
      "12px",

    fontWeight:
      "700"

  },


  cpRow: {

    display:
      "flex",

    gap:
      "8px"

  },


  cpButton: {

    border:
      "none",

    borderRadius:
      "10px",

    padding:
      "0 16px",

    background:
      "#344F72",

    color:
      "#FFFFFF",

    fontWeight:
      "700",

    cursor:
      "pointer"

  },


  activationCard: {

    display:
      "flex",

    alignItems:
      "flex-start",

    gap:
      "12px",

    padding:
      "18px",

    border:
      "1px solid #DCE5EF",

    borderRadius:
      "14px",

    background:
      "#F8FAFC",

    cursor:
      "pointer"

  },


  activationActive: {

    background:
      "#ECF9F1",

    border:
      "1px solid #A9DDBD"

  },


  requirementsGrid: {

    display:
      "grid",

    gridTemplateColumns:
      "repeat(auto-fit,minmax(230px,1fr))",

    gap:
      "10px"

  },


  requirement: {

    display:
      "flex",

    alignItems:
      "center",

    gap:
      "9px",

    padding:
      "12px",

    borderRadius:
      "10px",

    background:
      "#F6F8FA",

    color:
      "#687B91",

    fontSize:
      "13px",

    fontWeight:
      "600"

  },


  requirementComplete: {

    background:
      "#ECF9F1",

    color:
      "#2C794D"

  },


  requirementIcon: {

    fontWeight:
      "900",

    fontSize:
      "16px"

  },


  actions: {

    display:
      "flex",

    justifyContent:
      "flex-end",

    gap:
      "12px",

    flexWrap:
      "wrap",

    marginTop:
      "22px"

  },


  secondaryButton: {

    border:
      "1px solid #CCD7E5",

    background:
      "#FFFFFF",

    color:
      "#4D627C",

    borderRadius:
      "11px",

    padding:
      "13px 20px",

    cursor:
      "pointer",

    fontWeight:
      "700"

  },


  primaryButton: {

    border:
      "none",

    background:
      "#6848D3",

    color:
      "#FFFFFF",

    borderRadius:
      "11px",

    padding:
      "13px 22px",

    cursor:
      "pointer",

    fontWeight:
      "800",

    boxShadow:
      "0 6px 16px rgba(104,72,211,.23)"

  },


  disabledButton: {

    opacity:
      0.6,

    cursor:
      "not-allowed"

  },


  loadingCard: {

    background:
      "#FFFFFF",

    maxWidth:
      "500px",

    margin:
      "100px auto",

    padding:
      "40px",

    borderRadius:
      "18px",

    textAlign:
      "center",

    boxShadow:
      "0 8px 30px rgba(35,61,94,.08)"

  },


  loadingIcon: {

    fontSize:
      "42px",

    marginBottom:
      "10px"

  }

};


export default PerfilProfesionalPsicologo;