// ==================================================

// src/views/EmpleadoDetalle.jsx

// ==================================================



import React, {

  useCallback,

  useEffect,

  useState

} from "react";



import axios from "axios";



import {

  useNavigate,

  useParams

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



const EmpleadoDetalle = () => {



  const { idEmpleado } =

    useParams();



  const navigate =

    useNavigate();





  // ==================================================

  // ESTADOS

  // ==================================================



  const [

    empleado,

    setEmpleado

  ] = useState(null);



  const [

    resumenSeleccion,

    setResumenSeleccion

  ] = useState(null);



  const [

    documentos,

    setDocumentos

  ] = useState([]);



  const [

    totales,

    setTotales

  ] = useState({

    documentos: 0,

    evaluaciones_seleccion: 0

  });



  const [

    cargando,

    setCargando

  ] = useState(true);



  const [

    error,

    setError

  ] = useState("");



  const [

    mostrarFormularioDocumento,

    setMostrarFormularioDocumento

  ] = useState(false);



  const [

    archivoDocumento,

    setArchivoDocumento

  ] = useState(null);



  const [

    tipoDocumento,

    setTipoDocumento

  ] = useState("otro");



  const [

    descripcionDocumento,

    setDescripcionDocumento

  ] = useState("");



  const [

    subiendoDocumento,

    setSubiendoDocumento

  ] = useState(false);




  const [

    editandoPerfil,

    setEditandoPerfil

  ] = useState(false);



  const [

    guardandoPerfil,

    setGuardandoPerfil

  ] = useState(false);



  const [

    mensajePerfil,

    setMensajePerfil

  ] = useState("");



  const [

    buscandoCP,

    setBuscandoCP

  ] = useState(false);



  const [

    cpEncontrado,

    setCpEncontrado

  ] = useState(null);



  const [

    coloniasCP,

    setColoniasCP

  ] = useState([]);



  const [

    coloniaSeleccionada,

    setColoniaSeleccionada

  ] = useState("");



  const [

    formPerfil,

    setFormPerfil

  ] = useState({

    puesto: "",

    departamento: "",

    sueldo: "",

    periodicidad_sueldo: "",

    modalidad_trabajo: "",

    horario_laboral: "",

    codigo_postal_residencia: "",

    estado_residencia: "",

    municipio_residencia: "",

    colonia_residencia: "",

    fecha_contratacion: "",

    estatus: "activo"

  });





  // ==================================================

  // CARGAR EMPLEADO

  // ==================================================



  const cargarEmpleado =

    useCallback(

      async () => {



        try {



          setCargando(true);

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





          const respuesta =

            await axios.get(

              `${API_URL}/api/empleados/${idEmpleado}`,

              {

                headers: {

                  Authorization:

                    `Bearer ${token}`

                }

              }

            );





          console.log(

            "📦 Expediente laboral recibido:",

            respuesta.data

          );





          const empleadoEncontrado =

            respuesta.data?.empleado ||

            null;





          if (!empleadoEncontrado) {



            setEmpleado(null);



            setError(

              "Empleado no encontrado o no tienes permiso para acceder a él."

            );



            return;

          }





          setEmpleado(

            empleadoEncontrado

          );




          setFormPerfil({

            puesto:

              empleadoEncontrado.puesto ||

              "",

            departamento:

              empleadoEncontrado.departamento ||

              "",

            sueldo:

              empleadoEncontrado.sueldo ??

              "",

            periodicidad_sueldo:

              empleadoEncontrado

                .periodicidad_sueldo ||

              "",

            modalidad_trabajo:

              empleadoEncontrado

                .modalidad_trabajo ||

              "",

            horario_laboral:

              empleadoEncontrado

                .horario_laboral ||

              "",

            codigo_postal_residencia:

              empleadoEncontrado

                .codigo_postal_residencia ||

              "",

            estado_residencia:

              empleadoEncontrado

                .estado_residencia ||

              "",

            municipio_residencia:

              empleadoEncontrado

                .municipio_residencia ||

              "",

            colonia_residencia:

              empleadoEncontrado

                .colonia_residencia ||

              "",

            fecha_contratacion:

              empleadoEncontrado

                .fecha_contratacion

                ? String(

                    empleadoEncontrado

                      .fecha_contratacion

                  ).slice(

                    0,

                    10

                  )

                : "",

            estatus:

              empleadoEncontrado

                .estatus ||

              "activo"

          });



          setColoniaSeleccionada(

            empleadoEncontrado

              .colonia_residencia ||

            ""

          );



          setResumenSeleccion(

            respuesta.data

              ?.resumen_seleccion ||

            null

          );



          setDocumentos(

            Array.isArray(

              respuesta.data

                ?.documentos

            )

              ? respuesta.data

                  .documentos

              : []

          );



          setTotales({

            documentos:

              Number(

                respuesta.data

                  ?.totales

                  ?.documentos ||

                0

              ),



            evaluaciones_seleccion:

              Number(

                respuesta.data

                  ?.totales

                  ?.evaluaciones_seleccion ||

                0

              )

          });





        } catch (err) {



          console.error(

            "❌ Error cargando empleado RH:",

            err

          );





          setEmpleado(null);





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

        navigate

      ]

    );





  useEffect(

    () => {



      cargarEmpleado();



    },

    [

      cargarEmpleado

    ]

  );





  // ==================================================

  // AUXILIARES

  // ==================================================



  const formatearFecha =

    fecha => {



      if (!fecha) {

        return "No registrada";

      }



      const date =

        new Date(fecha);



      if (

        Number.isNaN(

          date.getTime()

        )

      ) {

        return fecha;

      }



      return date

        .toLocaleDateString(

          "es-MX",

          {

            year: "numeric",

            month: "long",

            day: "numeric"

          }

        );



    };





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





  const obtenerEstatus =

    estatus => {



      const estados = {



        activo: {

          texto:

            "Activo",

          fondo:

            "#ecfdf3",

          color:

            "#067647"

        },



        inactivo: {

          texto:

            "Inactivo",

          fondo:

            "#f2f4f7",

          color:

            "#475467"

        },



        baja: {

          texto:

            "Baja",

          fondo:

            "#fef3f2",

          color:

            "#b42318"

        }



      };





      return (

        estados[

          String(

            estatus || ""

          )

            .trim()

            .toLowerCase()

        ] ||

        estados.inactivo

      );



    };





  const obtenerNombreTipoDocumento =

    tipo => {



      const tipos = {



        cv:

          "Currículum",



        identificacion:

          "Identificación",



        constancia:

          "Constancia",



        certificado:

          "Certificado",



        comprobante:

          "Comprobante",



        contrato:

          "Contrato",



        otro:

          "Otro"



      };



      return (

        tipos[

          String(

            tipo || ""

          ).toLowerCase()

        ] ||

        "Documento"

      );



    };





  const obtenerUrlDocumento =

    documento => {



      const ruta =

        String(

          documento?.ruta_archivo ||

          ""

        ).trim();





      if (!ruta) {

        return "";

      }





      if (

        /^https?:\/\//i.test(

          ruta

        )

      ) {

        return ruta;

      }





      const rutaLimpia =

        ruta

          .replace(

            /\\/g,

            "/"

          )

          .replace(

            /^\/+/,

            ""

          );





      return (

        `${API_URL}/${rutaLimpia}`

      );



    };





  const obtenerPruebas =

    () => {



      const pruebas =

        resumenSeleccion

          ?.resumen_pruebas;



      return Array.isArray(

        pruebas

      )

        ? pruebas

        : [];



    };





  const obtenerResultadoPrueba =

    prueba => {



      if (

        prueba?.resultado

      ) {

        return prueba.resultado;

      }



      if (

        prueba?.resultado_texto

      ) {

        return prueba.resultado_texto;

      }



      if (

        prueba?.clasificacion

      ) {

        return prueba.clasificacion;

      }



      if (

        prueba?.puntaje_total !==

          null &&

        prueba?.puntaje_total !==

          undefined

      ) {

        return (

          `Puntaje: ${prueba.puntaje_total}`

        );

      }



      return "Resultado registrado";



    };





  // ==================================================

  // PERFIL LABORAL

  // ==================================================



  const formatearDinero =

    valor => {



      if (

        valor === null ||

        valor === undefined ||

        valor === ""

      ) {

        return "No registrado";

      }



      const numero =

        Number(

          valor

        );



      if (

        Number.isNaN(

          numero

        )

      ) {

        return valor;

      }



      return numero

        .toLocaleString(

          "es-MX",

          {

            style: "currency",

            currency: "MXN"

          }

        );

    };





  const capitalizar =

    valor => {



      if (!valor) {

        return "No especificado";

      }



      const texto =

        String(

          valor

        )

          .replaceAll(

            "_",

            " "

          );



      return (

        texto.charAt(0)

          .toUpperCase() +

        texto.slice(1)

      );

    };





  const cambiarCampoPerfil =

    event => {



      const {

        name,

        value

      } = event.target;



      setFormPerfil(

        actual => ({

          ...actual,

          [name]:

            value

        })

      );



      setMensajePerfil("");

    };





  const buscarCodigoPostal =

    useCallback(

      async codigoPostal => {



        const cp =

          String(

            codigoPostal ||

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

          setCpEncontrado(

            null

          );



          setColoniasCP(

            []

          );



          return;

        }



        try {



          setBuscandoCP(

            true

          );



          const token =

            getToken();



          const respuesta =

            await axios.get(

              `${API_URL}/api/codigos-postales/${cp}`,

              {

                headers:

                  token

                    ? {

                        Authorization:

                          `Bearer ${token}`

                      }

                    : {}

              }

            );



          const datos =

            respuesta.data ||

            {};



          const colonias =

            Array.isArray(

              datos.colonias

            )

              ? datos.colonias

                  .map(

                    item =>

                      typeof item ===

                      "string"

                        ? item

                        : item?.nombre ||

                          item

                            ?.colonia ||

                          ""

                  )

                  .filter(

                    Boolean

                  )

              : [];



          const estado =

            datos.estado ||

            datos

              .estado_residencia ||

            "";



          const municipio =

            datos.municipio ||

            datos

              .municipio_residencia ||

            datos.alcaldia ||

            "";



          setCpEncontrado(

            true

          );



          setColoniasCP(

            colonias

          );



          setFormPerfil(

            actual => {



              let colonia =

                actual

                  .colonia_residencia;



              if (

                colonias.length

              ) {



                const encontrada =

                  colonias.find(

                    item =>

                      item

                        .toLowerCase() ===

                      String(

                        colonia ||

                        ""

                      )

                        .toLowerCase()

                  );



                if (encontrada) {

                  setColoniaSeleccionada(

                    encontrada

                  );



                  colonia =

                    encontrada;

                } else {

                  setColoniaSeleccionada(

                    "__otra__"

                  );

                }



              } else {

                setColoniaSeleccionada(

                  "__otra__"

                );

              }



              return {

                ...actual,

                codigo_postal_residencia:

                  cp,

                estado_residencia:

                  estado,

                municipio_residencia:

                  municipio,

                colonia_residencia:

                  colonia

              };

            }

          );



        } catch (err) {



          console.warn(

            "⚠️ Código postal no encontrado:",

            err.response?.data ||

            err.message

          );



          setCpEncontrado(

            false

          );



          setColoniasCP(

            []

          );



          setColoniaSeleccionada(

            "__otra__"

          );



        } finally {



          setBuscandoCP(

            false

          );

        }

      },

      []

    );





  useEffect(

    () => {



      if (

        !editandoPerfil

      ) {

        return;

      }



      const cp =

        String(

          formPerfil

            .codigo_postal_residencia ||

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

        setCpEncontrado(

          null

        );



        setColoniasCP(

          []

        );



        return;

      }



      const temporizador =

        setTimeout(

          () => {

            buscarCodigoPostal(

              cp

            );

          },

          450

        );



      return () =>

        clearTimeout(

          temporizador

        );

    },

    [

      editandoPerfil,

      formPerfil

        .codigo_postal_residencia,

      buscarCodigoPostal

    ]

  );





  const cancelarEdicionPerfil =

    () => {



      if (!empleado) {

        return;

      }



      setFormPerfil({

        puesto:

          empleado.puesto ||

          "",

        departamento:

          empleado.departamento ||

          "",

        sueldo:

          empleado.sueldo ??

          "",

        periodicidad_sueldo:

          empleado

            .periodicidad_sueldo ||

          "",

        modalidad_trabajo:

          empleado

            .modalidad_trabajo ||

          "",

        horario_laboral:

          empleado

            .horario_laboral ||

          "",

        codigo_postal_residencia:

          empleado

            .codigo_postal_residencia ||

          "",

        estado_residencia:

          empleado

            .estado_residencia ||

          "",

        municipio_residencia:

          empleado

            .municipio_residencia ||

          "",

        colonia_residencia:

          empleado

            .colonia_residencia ||

          "",

        fecha_contratacion:

          empleado

            .fecha_contratacion

            ? String(

                empleado

                  .fecha_contratacion

              ).slice(

                0,

                10

              )

            : "",

        estatus:

          empleado.estatus ||

          "activo"

      });



      setColoniaSeleccionada(

        empleado

          .colonia_residencia ||

        ""

      );



      setCpEncontrado(

        null

      );



      setColoniasCP(

        []

      );



      setMensajePerfil("");



      setEditandoPerfil(

        false

      );

    };





  const guardarPerfilLaboral =

    async event => {



      event.preventDefault();



      try {



        setGuardandoPerfil(

          true

        );



        setError("");



        setMensajePerfil("");



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



        const payload = {

          puesto:

            formPerfil.puesto

              .trim() ||

            null,

          departamento:

            formPerfil

              .departamento

              .trim() ||

            null,

          sueldo:

            formPerfil.sueldo ===

            ""

              ? null

              : Number(

                  formPerfil

                    .sueldo

                ),

          periodicidad_sueldo:

            formPerfil

              .periodicidad_sueldo ||

            null,

          modalidad_trabajo:

            formPerfil

              .modalidad_trabajo ||

            null,

          horario_laboral:

            formPerfil

              .horario_laboral

              .trim() ||

            null,

          codigo_postal_residencia:

            formPerfil

              .codigo_postal_residencia

              .trim() ||

            null,

          estado_residencia:

            formPerfil

              .estado_residencia

              .trim() ||

            null,

          municipio_residencia:

            formPerfil

              .municipio_residencia

              .trim() ||

            null,

          colonia_residencia:

            formPerfil

              .colonia_residencia

              .trim() ||

            null,

          fecha_contratacion:

            formPerfil

              .fecha_contratacion ||

            null,

          estatus:

            formPerfil.estatus

        };



        const respuesta =

          await axios.put(

            `${API_URL}/api/empleados/${idEmpleado}`,

            payload,

            {

              headers: {

                Authorization:

                  `Bearer ${token}`

              }

            }

          );



        setMensajePerfil(

          respuesta.data

            ?.message ||

          "Perfil laboral actualizado correctamente."

        );



        setEditandoPerfil(

          false

        );



        await cargarEmpleado();



      } catch (err) {



        console.error(

          "❌ Error guardando perfil laboral:",

          err

        );



        setError(

          err.response?.data

            ?.message ||

          "No fue posible guardar el perfil laboral."

        );



      } finally {



        setGuardandoPerfil(

          false

        );

      }

    };





  // ==================================================

  // SUBIR DOCUMENTO

  // ==================================================



  const subirDocumento =

    async event => {



      event.preventDefault();





      if (!archivoDocumento) {



        alert(

          "Selecciona un archivo."

        );



        return;

      }





      try {



        setSubiendoDocumento(

          true

        );





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





        const formData =

          new FormData();





        formData.append(

          "file",

          archivoDocumento

        );



        formData.append(

          "tipo_documento",

          tipoDocumento

        );



        formData.append(

          "descripcion",

          descripcionDocumento

        );





        await axios.post(

          `${API_URL}/api/empleados/${idEmpleado}/documentos`,

          formData,

          {

            headers: {

              Authorization:

                `Bearer ${token}`

            }

          }

        );





        setArchivoDocumento(

          null

        );



        setTipoDocumento(

          "otro"

        );



        setDescripcionDocumento(

          ""

        );



        setMostrarFormularioDocumento(

          false

        );





        await cargarEmpleado();





      } catch (err) {



        console.error(

          "❌ Error subiendo documento del empleado:",

          err

        );





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





        if (

          err.response?.status ===

          404

        ) {



          alert(

            "La ruta para subir documentos del empleado todavía no está habilitada en el backend."

          );



          return;

        }





        alert(

          err.response?.data?.message ||

          "No se pudo subir el documento."

        );





      } finally {



        setSubiendoDocumento(

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



          <div style={styles.backButtonRow}>
          <button
            type="button"
            style={styles.backButton}
            onClick={() =>
              navigate(
                "/empleados"
              )
            }
          >
            <span style={styles.backButtonText}>
              ← Volver a empleados
            </span>
          </button>
        </div>





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





  const pruebas =

    obtenerPruebas();





  // ==================================================

  // RENDER

  // ==================================================



  return (



    <div style={styles.page}>



      <div style={styles.container}>





        {/* ==========================================

            VOLVER

        ========================================== */}



        <div style={styles.backButtonRow}>
          <button
            type="button"
            style={styles.backButton}
            onClick={() =>
              navigate(
                "/empleados"
              )
            }
          >
            <span style={styles.backButtonText}>
              ← Volver a empleados
            </span>
          </button>
        </div>





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




                <span

                  style={{

                    ...styles.profileBadge,

                    ...(Number(

                      empleado

                        .perfil_laboral_completo

                    ) === 1

                      ? styles

                          .profileComplete

                      : styles

                          .profileIncomplete)

                  }}

                >

                  {

                    Number(

                      empleado

                        .perfil_laboral_completo

                    ) === 1

                      ? "✓ Perfil laboral completo"

                      : "⚠ Perfil laboral incompleto"

                  }

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



        </div>





        {/* ==========================================

            PERFIL LABORAL

        ========================================== */}



        <div style={styles.card}>



          <div style={styles.cardHeaderRow}>



            <div>



              <h2 style={styles.cardTitle}>

                👔 Perfil laboral

              </h2>



              <p style={styles.cardSubtitle}>

                Completa los datos finales de contratación. El sueldo y la ubicación también ayudarán a mejorar las opciones de canalización.

              </p>



            </div>





            {!editandoPerfil && (



              <button

                type="button"

                style={styles.primaryButton}

                onClick={() => {



                  setError("");



                  setMensajePerfil("");



                  setEditandoPerfil(

                    true

                  );



                }}

              >

                ✏️ Editar perfil laboral

              </button>



            )}



          </div>





          {mensajePerfil && (



            <div style={styles.successBox}>

              ✅ {mensajePerfil}

            </div>



          )}





          <div

            style={{

              ...styles.profileStatusBox,

              ...(Number(

                empleado

                  .perfil_laboral_completo

              ) === 1

                ? styles

                    .profileStatusComplete

                : styles

                    .profileStatusIncomplete)

            }}

          >



            <strong>

              {

                Number(

                  empleado

                    .perfil_laboral_completo

                ) === 1

                  ? "✓ Perfil laboral completo"

                  : "⚠ Perfil laboral incompleto"

              }

            </strong>



            <span>

              {

                Number(

                  empleado

                    .perfil_laboral_completo

                ) === 1

                  ? "Los principales datos de contratación ya están completos."

                  : "Completa puesto, departamento, contratación, sueldo, periodicidad, modalidad y ubicación."

              }

            </span>



          </div>





          {editandoPerfil ? (



            <form

              onSubmit={

                guardarPerfilLaboral

              }

            >



              <div style={styles.profileFormGrid}>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Puesto *

                  </label>



                  <input

                    type="text"

                    name="puesto"

                    value={

                      formPerfil.puesto

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                    placeholder="Ej. Analista administrativo"

                  />



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Departamento / área *

                  </label>



                  <input

                    type="text"

                    name="departamento"

                    value={

                      formPerfil

                        .departamento

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                    placeholder="Ej. Administración"

                  />



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Fecha de contratación *

                  </label>



                  <input

                    type="date"

                    name="fecha_contratacion"

                    value={

                      formPerfil

                        .fecha_contratacion

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                  />



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Estado laboral

                  </label>



                  <select

                    name="estatus"

                    value={

                      formPerfil.estatus

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                  >

                    <option value="activo">

                      Activo

                    </option>



                    <option value="inactivo">

                      Inactivo

                    </option>



                    <option value="baja">

                      Baja

                    </option>

                  </select>



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Sueldo *

                  </label>



                  <input

                    type="number"

                    min="0"

                    step="0.01"

                    name="sueldo"

                    value={

                      formPerfil.sueldo

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                    placeholder="Ej. 3000"

                  />



                  <small style={styles.helperText}>

                    Registra el monto según la periodicidad seleccionada.

                  </small>



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Periodicidad del sueldo *

                  </label>



                  <select

                    name="periodicidad_sueldo"

                    value={

                      formPerfil

                        .periodicidad_sueldo

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                  >

                    <option value="">

                      Selecciona

                    </option>



                    <option value="semanal">

                      Semanal

                    </option>



                    <option value="quincenal">

                      Quincenal

                    </option>



                    <option value="mensual">

                      Mensual

                    </option>

                  </select>



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Modalidad de trabajo *

                  </label>



                  <select

                    name="modalidad_trabajo"

                    value={

                      formPerfil

                        .modalidad_trabajo

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                  >

                    <option value="">

                      Selecciona

                    </option>



                    <option value="presencial">

                      Presencial

                    </option>



                    <option value="hibrido">

                      Híbrido

                    </option>



                    <option value="remoto">

                      Remoto

                    </option>

                  </select>



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Horario laboral

                  </label>



                  <input

                    type="text"

                    name="horario_laboral"

                    value={

                      formPerfil

                        .horario_laboral

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    style={styles.input}

                    placeholder="Ej. L-V 09:00 a 18:00"

                  />



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Código postal de residencia *

                  </label>



                  <input

                    type="text"

                    inputMode="numeric"

                    maxLength={5}

                    name="codigo_postal_residencia"

                    value={

                      formPerfil

                        .codigo_postal_residencia

                    }

                    onChange={

                      event => {



                        const limpio =

                          event.target.value

                            .replace(

                              /\D/g,

                              ""

                            )

                            .slice(

                              0,

                              5

                            );



                        setFormPerfil(

                          actual => ({

                            ...actual,

                            codigo_postal_residencia:

                              limpio

                          })

                        );



                        setMensajePerfil("");



                      }

                    }

                    style={styles.input}

                    placeholder="Ej. 56400"

                  />



                  {buscandoCP && (



                    <small style={styles.helperText}>

                      🔎 Buscando ubicación...

                    </small>



                  )}



                  {

                    cpEncontrado ===

                      true &&

                    !buscandoCP && (



                      <small style={styles.successTextSmall}>

                        ✓ Código postal encontrado

                      </small>



                    )

                  }



                  {

                    cpEncontrado ===

                      false &&

                    !buscandoCP && (



                      <small style={styles.warningTextSmall}>

                        ⚠ No encontramos el CP. Puedes llenar la ubicación manualmente.

                      </small>



                    )

                  }



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Estado *

                  </label>



                  <input

                    type="text"

                    name="estado_residencia"

                    value={

                      formPerfil

                        .estado_residencia

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    readOnly={

                      cpEncontrado ===

                      true

                    }

                    style={{

                      ...styles.input,

                      ...(cpEncontrado ===

                      true

                        ? styles

                            .readOnlyInput

                        : {})

                    }}

                    placeholder="Ej. Estado de México"

                  />



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Municipio / alcaldía *

                  </label>



                  <input

                    type="text"

                    name="municipio_residencia"

                    value={

                      formPerfil

                        .municipio_residencia

                    }

                    onChange={

                      cambiarCampoPerfil

                    }

                    readOnly={

                      cpEncontrado ===

                      true

                    }

                    style={{

                      ...styles.input,

                      ...(cpEncontrado ===

                      true

                        ? styles

                            .readOnlyInput

                        : {})

                    }}

                    placeholder="Ej. La Paz"

                  />



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Colonia *

                  </label>



                  {

                    cpEncontrado ===

                      true &&

                    coloniasCP.length >

                      0

                      ? (



                        <>

                          <select

                            value={

                              coloniaSeleccionada

                            }

                            onChange={

                              event => {



                                const valor =

                                  event

                                    .target

                                    .value;



                                setColoniaSeleccionada(

                                  valor

                                );



                                if (

                                  valor !==

                                  "__otra__"

                                ) {



                                  setFormPerfil(

                                    actual => ({

                                      ...actual,

                                      colonia_residencia:

                                        valor

                                    })

                                  );



                                } else {



                                  setFormPerfil(

                                    actual => ({

                                      ...actual,

                                      colonia_residencia:

                                        ""

                                    })

                                  );



                                }

                              }

                            }

                            style={styles.input}

                          >

                            <option value="">

                              Selecciona una colonia

                            </option>



                            {

                              coloniasCP.map(

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

                              )

                            }



                            <option value="__otra__">

                              Otra / No aparece

                            </option>

                          </select>



                          {

                            coloniaSeleccionada ===

                              "__otra__" && (



                              <input

                                type="text"

                                name="colonia_residencia"

                                value={

                                  formPerfil

                                    .colonia_residencia

                                }

                                onChange={

                                  cambiarCampoPerfil

                                }

                                style={{

                                  ...styles.input,

                                  marginTop:

                                    "8px"

                                }}

                                placeholder="Escribe la colonia"

                              />



                            )

                          }

                        </>



                      )

                      : (



                        <input

                          type="text"

                          name="colonia_residencia"

                          value={

                            formPerfil

                              .colonia_residencia

                          }

                          onChange={

                            cambiarCampoPerfil

                          }

                          style={styles.input}

                          placeholder="Escribe la colonia"

                        />



                      )

                  }



                </div>



              </div>





              <div style={styles.privateNotice}>



                <strong>

                  🔒 Uso interno de RH

                </strong>



                <span>

                  El sueldo y la ubicación se utilizarán para mejorar la compatibilidad de las opciones de canalización. No forman parte del expediente clínico.

                </span>



              </div>





              <div style={styles.profileActions}>



                <button

                  type="button"

                  style={styles.secondaryButton}

                  onClick={

                    cancelarEdicionPerfil

                  }

                  disabled={

                    guardandoPerfil

                  }

                >

                  Cancelar

                </button>





                <button

                  type="submit"

                  disabled={

                    guardandoPerfil

                  }

                  style={{

                    ...styles.primaryButton,

                    opacity:

                      guardandoPerfil

                        ? 0.6

                        : 1

                  }}

                >

                  {

                    guardandoPerfil

                      ? "Guardando..."

                      : "Guardar perfil laboral"

                  }

                </button>



              </div>



            </form>



          ) : (



            <>



              <div style={styles.infoGrid}>



                <InfoItem

                  label="Puesto"

                  value={

                    empleado.puesto ||

                    "No especificado"

                  }

                />



                <InfoItem

                  label="Departamento"

                  value={

                    empleado.departamento ||

                    "No especificado"

                  }

                />



                <InfoItem

                  label="Fecha de contratación"

                  value={

                    formatearFecha(

                      empleado

                        .fecha_contratacion

                    )

                  }

                />



                <InfoItem

                  label="Estado laboral"

                  value={

                    estado.texto

                  }

                />



                <InfoItem

                  label="Sueldo"

                  value={

                    `${formatearDinero(

                      empleado.sueldo

                    )} · ${

                      empleado

                        .periodicidad_sueldo

                        ? capitalizar(

                            empleado

                              .periodicidad_sueldo

                          )

                        : "Periodicidad no registrada"

                    }`

                  }

                />



                <InfoItem

                  label="Modalidad de trabajo"

                  value={

                    capitalizar(

                      empleado

                        .modalidad_trabajo

                    )

                  }

                />



                <InfoItem

                  label="Horario laboral"

                  value={

                    empleado

                      .horario_laboral ||

                    "No registrado"

                  }

                />



                <InfoItem

                  label="Código postal"

                  value={

                    empleado

                      .codigo_postal_residencia ||

                    "No registrado"

                  }

                />



                <InfoItem

                  label="Estado de residencia"

                  value={

                    empleado

                      .estado_residencia ||

                    "No registrado"

                  }

                />



                <InfoItem

                  label="Municipio / alcaldía"

                  value={

                    empleado

                      .municipio_residencia ||

                    "No registrado"

                  }

                />



                <InfoItem

                  label="Colonia"

                  value={

                    empleado

                      .colonia_residencia ||

                    "No registrada"

                  }

                />



              </div>





              <div style={styles.privateNotice}>



                <strong>

                  🔒 Datos para compatibilidad de canalización

                </strong>



                <span>

                  La ubicación y el rango económico permiten priorizar profesionales adecuados para el empleado.

                </span>



              </div>



            </>



          )}



        </div>





        {/* ==========================================

            DATOS GENERALES

        ========================================== */}



        <div style={styles.card}>



          <div style={styles.cardHeader}>



            <div>



              <h2 style={styles.cardTitle}>

                👤 Datos generales

              </h2>



              <p style={styles.cardSubtitle}>

                Información identificativa del empleado.

              </p>



            </div>



          </div>





          <div style={styles.infoGrid}>



            <InfoItem

              label="ID MirrorSoul"

              value={

                empleado.id_mirror ||

                "No asignado"

              }

            />



            <InfoItem

              label="Edad"

              value={

                empleado.edad

                  ? `${empleado.edad} años`

                  : "No registrada"

              }

            />



            <InfoItem

              label="Sexo"

              value={

                textoSexo(

                  empleado.sexo

                )

              }

            />



            <InfoItem

              label="Correo"

              value={

                empleado.correo ||

                "No registrado"

              }

            />



            <InfoItem

              label="Teléfono"

              value={

                empleado.telefono ||

                "No registrado"

              }

            />



            <InfoItem

              label="Dirección"

              value={

                empleado.direccion ||

                "No registrada"

              }

            />



          </div>



        </div>





        {/* ==========================================

            RESUMEN DEL PROCESO DE INGRESO

        ========================================== */}



        <div style={styles.card}>



          <div style={styles.cardHeaderRow}>



            <div>



              <h2 style={styles.cardTitle}>

                📋 Resumen del proceso de ingreso

              </h2>



              <p style={styles.cardSubtitle}>

                Información relevante conservada al finalizar la selección.

              </p>



            </div>





            <span style={styles.hiredBadge}>

              ✅ Contratado

            </span>



          </div>





          {resumenSeleccion ? (



            <>



              <div style={styles.summaryGrid}>



                <div style={styles.summaryItem}>



                  <span style={styles.summaryLabel}>

                    Resultado

                  </span>



                  <strong style={styles.successText}>

                    Contratado

                  </strong>



                </div>





                <div style={styles.summaryItem}>



                  <span style={styles.summaryLabel}>

                    Fecha de decisión

                  </span>



                  <strong>

                    {

                      formatearFecha(

                        resumenSeleccion

                          .fecha_decision

                      )

                    }

                  </strong>



                </div>





                <div style={styles.summaryItem}>



                  <span style={styles.summaryLabel}>

                    Evaluaciones

                  </span>



                  <strong>

                    {

                      totales

                        .evaluaciones_seleccion

                    }

                  </strong>



                </div>





                <div style={styles.summaryItem}>



                  <span style={styles.summaryLabel}>

                    Documentos transferidos

                  </span>



                  <strong>

                    {totales.documentos}

                  </strong>



                </div>



              </div>





              <div style={styles.summaryTextBox}>



                <span style={styles.summaryLabel}>

                  Motivo de contratación

                </span>



                <p style={styles.summaryText}>

                  {

                    resumenSeleccion

                      .motivo ||

                    "Sin motivo registrado."

                  }

                </p>



              </div>





              <div style={styles.summaryTextBox}>



                <span style={styles.summaryLabel}>

                  Observación final

                </span>



                <p style={styles.summaryText}>

                  {

                    resumenSeleccion

                      .observacion_final ||

                    "Sin observación final."

                  }

                </p>



              </div>





              {/* ======================================

                  PRUEBAS RESUMIDAS

              ====================================== */}



              <div style={styles.testsSection}>



                <div style={styles.subsectionTitle}>

                  🧪 Evaluaciones realizadas durante selección

                </div>





                {pruebas.length === 0 ? (



                  <div style={styles.smallEmpty}>

                    No se conservaron resultados resumidos de evaluaciones.

                  </div>



                ) : (



                  <div style={styles.testsGrid}>



                    {pruebas.map(

                      (

                        prueba,

                        index

                      ) => (



                        <div

                          key={

                            `${prueba?.prueba || "prueba"}-${index}`

                          }

                          style={styles.testCard}

                        >



                          <div style={styles.testName}>

                            {

                              prueba?.prueba ||

                              `Evaluación ${index + 1}`

                            }

                          </div>





                          <div style={styles.testResult}>

                            {

                              obtenerResultadoPrueba(

                                prueba

                              )

                            }

                          </div>





                          {

                            prueba

                              ?.interpretacion_laboral && (



                              <p style={styles.testText}>

                                {

                                  prueba

                                    .interpretacion_laboral

                                }

                              </p>



                            )

                          }



                        </div>



                      )

                    )}



                  </div>



                )}



              </div>



            </>



          ) : (



            <div style={styles.smallEmpty}>



              No se encontró un resumen de selección para este empleado.



            </div>



          )}



        </div>





        {/* ==========================================

            DOCUMENTOS DEL EMPLEADO

        ========================================== */}



        <div style={styles.card}>



          <div style={styles.cardHeaderRow}>



            <div>



              <h2 style={styles.cardTitle}>

                📁 Documentos del empleado

              </h2>



              <p style={styles.cardSubtitle}>

                Documentos transferidos del proceso de selección y documentos laborales agregados posteriormente.

              </p>



            </div>





            <button

              type="button"

              style={styles.primaryButton}

              onClick={() =>

                setMostrarFormularioDocumento(

                  actual =>

                    !actual

                )

              }

            >

              {

                mostrarFormularioDocumento

                  ? "Cancelar"

                  : "+ Agregar documento"

              }

            </button>



          </div>





          {/* ======================================

              FORMULARIO DOCUMENTO

          ====================================== */}



          {mostrarFormularioDocumento && (



            <form

              style={styles.uploadBox}

              onSubmit={

                subirDocumento

              }

            >



              <div style={styles.uploadGrid}>



                <div style={styles.field}>



                  <label style={styles.label}>

                    Tipo de documento

                  </label>



                  <select

                    value={

                      tipoDocumento

                    }

                    onChange={

                      e =>

                        setTipoDocumento(

                          e.target.value

                        )

                    }

                    style={styles.input}

                  >

                    <option value="cv">

                      Currículum

                    </option>



                    <option value="identificacion">

                      Identificación

                    </option>



                    <option value="constancia">

                      Constancia

                    </option>



                    <option value="certificado">

                      Certificado

                    </option>



                    <option value="comprobante">

                      Comprobante

                    </option>



                    <option value="contrato">

                      Contrato

                    </option>



                    <option value="otro">

                      Otro

                    </option>

                  </select>



                </div>





                <div style={styles.field}>



                  <label style={styles.label}>

                    Archivo

                  </label>



                  <input

                    type="file"

                    onChange={

                      e =>

                        setArchivoDocumento(

                          e.target.files?.[0] ||

                          null

                        )

                    }

                    style={styles.input}

                  />



                </div>



              </div>





              <div style={styles.field}>



                <label style={styles.label}>

                  Descripción

                </label>



                <input

                  type="text"

                  value={

                    descripcionDocumento

                  }

                  onChange={

                    e =>

                      setDescripcionDocumento(

                        e.target.value

                      )

                  }

                  placeholder="Ej. Contrato laboral firmado"

                  style={styles.input}

                />



              </div>





              <div style={styles.uploadActions}>



                <button

                  type="submit"

                  disabled={

                    subiendoDocumento

                  }

                  style={{

                    ...styles.primaryButton,



                    opacity:

                      subiendoDocumento

                        ? 0.6

                        : 1

                  }}

                >

                  {

                    subiendoDocumento

                      ? "Subiendo..."

                      : "📤 Guardar documento"

                  }

                </button>



              </div>



            </form>



          )}





          {/* ======================================

              LISTA DE DOCUMENTOS

          ====================================== */}



          {documentos.length === 0 ? (



            <div style={styles.emptyDocuments}>



              <div style={styles.emptyDocumentIcon}>

                📄

              </div>



              <strong>

                Sin documentos

              </strong>



              <p>

                Todavía no hay documentos registrados en el expediente laboral.

              </p>



            </div>



          ) : (



            <div style={styles.documentsList}>



              {documentos.map(

                documento => {



                  const url =

                    obtenerUrlDocumento(

                      documento

                    );



                  return (



                    <div

                      key={

                        documento.id_documento

                      }

                      style={styles.documentRow}

                    >



                      <div style={styles.documentIcon}>

                        📄

                      </div>





                      <div style={styles.documentInfo}>



                        <div style={styles.documentName}>



                          {

                            documento.nombre_original ||

                            documento.nombre_archivo ||

                            "Documento"

                          }



                        </div>





                        <div style={styles.documentMeta}>



                          {

                            obtenerNombreTipoDocumento(

                              documento

                                .tipo_documento

                            )

                          }



                          {" · "}



                          {

                            formatearFecha(

                              documento

                                .fecha_subida

                            )

                          }



                        </div>





                        {documento.descripcion && (



                          <div style={styles.documentDescription}>

                            {

                              documento.descripcion

                            }

                          </div>



                        )}



                      </div>





                      {url && (



                        <a

                          href={url}

                          target="_blank"

                          rel="noreferrer"

                          style={styles.viewDocumentButton}

                        >

                          Ver documento

                        </a>



                      )}



                    </div>



                  );



                }

              )}



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

                🧩 Gestión y seguimiento del personal

              </h2>



              <p style={styles.cardSubtitle}>

                Herramientas para supervisar avances, identificar necesidades y fortalecer el desempeño.

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

                📊

              </div>



              <h3>

                Expediente laboral

              </h3>



              <p>

                Registra evolución, situaciones relevantes, acuerdos y acciones de seguimiento.

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

                Aplica evaluaciones de seguimiento y prevención durante la relación laboral.

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

                Consulta indicadores laborales y registra acciones preventivas.

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

                Módulo para seguimiento de factores de riesgo psicosocial relacionados con el trabajo.

              </p>







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

                Facilita opciones de apoyo profesional cuando se detecten indicadores que requieran atención especializada.

              </p>






            </button>



          </div>



        </div>



      </div>



    </div>



  );



};





// ==================================================

// COMPONENTE PEQUEÑO DE INFORMACIÓN

// ==================================================



const InfoItem = ({

  label,

  value

}) => {



  return (



    <div style={styles.infoItem}>



      <span style={styles.infoLabel}>

        {label}

      </span>



      <strong style={styles.breakText}>

        {value}

      </strong>



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
  backButtonRow: {
    position: "relative",
    zIndex: 9999,
    display: "flex",
    alignItems: "center",
    justifyContent: "flex-start",
    width: "100%",
    marginBottom: "18px",
    pointerEvents: "auto"
  },

  backButton: {
    appearance: "none",
    WebkitAppearance: "none",
    position: "relative",
    zIndex: 10000,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    minWidth: "240px",
    minHeight: "46px",
    padding: "12px 24px",
    margin: 0,
    border: "none",
    borderRadius: "999px",
    background:
      "linear-gradient(135deg,#64B5F6,#1976D2)",
    color: "#ffffff",
    cursor: "pointer",
    fontWeight: "700",
    fontSize: "16px",
    lineHeight: 1.2,
    boxShadow:
      "0 5px 14px rgba(25,118,210,.25)",
    pointerEvents: "auto",
    userSelect: "none",
    WebkitUserSelect: "none",
    touchAction: "manipulation",
    whiteSpace: "nowrap"
  },

  backButtonText: {
    display: "block",
    width: "100%",
    textAlign: "center",
    pointerEvents: "none"
  },

  headerCard: {

    background: "#ffffff",

    borderRadius: "18px",

    padding: "24px",

    marginBottom: "22px",

    boxShadow:

      "0 4px 18px rgba(0,0,0,.05)"

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

    background:

      "linear-gradient(135deg,#e8eef9,#dbeafe)",

    color: "#17345F",

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

    fontSize: "29px",

    color: "#172B4D"

  },



  statusBadge: {

    borderRadius: "20px",

    padding: "5px 10px",

    fontSize: "12px",

    fontWeight: "700"

  },




  profileBadge: {

    borderRadius: "20px",

    padding: "5px 10px",

    fontSize: "12px",

    fontWeight: "800"

  },



  profileComplete: {

    background: "#ECFDF3",

    color: "#067647",

    border: "1px solid #ABEFC6"

  },



  profileIncomplete: {

    background: "#FFFAEB",

    color: "#B54708",

    border: "1px solid #FEDF89"

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



  cardHeaderRow: {

    marginBottom: "20px",

    display: "flex",

    alignItems: "center",

    justifyContent: "space-between",

    gap: "20px",

    flexWrap: "wrap"

  },



  cardTitle: {

    margin: "0 0 5px",

    color: "#172B4D"

  },



  cardSubtitle: {

    margin: 0,

    color: "#667085",

    lineHeight: 1.5

  },




  profileStatusBox: {

    borderRadius: "12px",

    padding: "14px 16px",

    marginBottom: "18px",

    display: "flex",

    flexDirection: "column",

    gap: "4px"

  },



  profileStatusComplete: {

    background: "#ECFDF3",

    border: "1px solid #ABEFC6",

    color: "#067647"

  },



  profileStatusIncomplete: {

    background: "#FFFAEB",

    border: "1px solid #FEDF89",

    color: "#B54708"

  },



  profileFormGrid: {

    display: "grid",

    gridTemplateColumns:

      "repeat(auto-fit, minmax(220px, 1fr))",

    gap: "12px"

  },



  profileActions: {

    display: "flex",

    justifyContent: "flex-end",

    gap: "10px",

    marginTop: "18px",

    flexWrap: "wrap"

  },



  privateNotice: {

    marginTop: "16px",

    background: "#F8FAFC",

    border: "1px solid #E4E7EC",

    borderRadius: "10px",

    padding: "13px 14px",

    display: "flex",

    flexDirection: "column",

    gap: "4px",

    color: "#475467",

    fontSize: "12px",

    lineHeight: 1.5

  },



  readOnlyInput: {

    background: "#F2F4F7",

    color: "#667085",

    cursor: "not-allowed"

  },



  helperText: {

    color: "#667085",

    fontSize: "11px",

    lineHeight: 1.4

  },



  successTextSmall: {

    color: "#067647",

    fontSize: "11px",

    fontWeight: "700"

  },



  warningTextSmall: {

    color: "#B54708",

    fontSize: "11px",

    fontWeight: "700",

    lineHeight: 1.4

  },



  successBox: {

    marginBottom: "14px",

    background: "#ECFDF3",

    border: "1px solid #ABEFC6",

    color: "#067647",

    borderRadius: "10px",

    padding: "11px 13px",

    fontWeight: "700"

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





  // ==================================================

  // RESUMEN DE SELECCIÓN

  // ==================================================



  hiredBadge: {

    background: "#ECFDF3",

    color: "#067647",

    border: "1px solid #ABEFC6",

    borderRadius: "20px",

    padding: "7px 12px",

    fontSize: "12px",

    fontWeight: "800"

  },



  summaryGrid: {

    display: "grid",

    gridTemplateColumns:

      "repeat(auto-fit, minmax(170px, 1fr))",

    gap: "12px",

    marginBottom: "16px"

  },



  summaryItem: {

    padding: "13px",

    background: "#F8FAFC",

    borderRadius: "10px",

    display: "flex",

    flexDirection: "column",

    gap: "5px"

  },



  summaryLabel: {

    fontSize: "11px",

    fontWeight: "800",

    color: "#667085",

    textTransform: "uppercase"

  },



  successText: {

    color: "#067647"

  },



  summaryTextBox: {

    padding: "14px",

    background: "#FBFCFE",

    border: "1px solid #EAECF0",

    borderRadius: "10px",

    marginTop: "10px"

  },



  summaryText: {

    margin: "6px 0 0",

    lineHeight: 1.55,

    color: "#344054"

  },



  testsSection: {

    marginTop: "20px",

    paddingTop: "18px",

    borderTop: "1px solid #EAECF0"

  },



  subsectionTitle: {

    fontWeight: "800",

    color: "#344054",

    marginBottom: "12px"

  },



  testsGrid: {

    display: "grid",

    gridTemplateColumns:

      "repeat(auto-fit, minmax(220px, 1fr))",

    gap: "10px"

  },



  testCard: {

    padding: "13px",

    border: "1px solid #E4E7EC",

    background: "#FCFCFD",

    borderRadius: "10px"

  },



  testName: {

    fontSize: "13px",

    fontWeight: "800",

    color: "#344054"

  },



  testResult: {

    marginTop: "5px",

    color: "#2167D5",

    fontWeight: "700",

    fontSize: "12px"

  },



  testText: {

    margin: "7px 0 0",

    color: "#667085",

    fontSize: "12px",

    lineHeight: 1.45

  },





  // ==================================================

  // DOCUMENTOS

  // ==================================================



  primaryButton: {

    border: "none",

    background: "#2867D7",

    color: "#FFFFFF",

    padding: "10px 15px",

    borderRadius: "10px",

    cursor: "pointer",

    fontWeight: "800"

  },




  secondaryButton: {

    border: "1px solid #D0D5DD",

    background: "#FFFFFF",

    color: "#344054",

    padding: "10px 15px",

    borderRadius: "10px",

    cursor: "pointer",

    fontWeight: "700"

  },



  uploadBox: {

    background: "#F8FAFC",

    border: "1px solid #E4E7EC",

    borderRadius: "12px",

    padding: "16px",

    marginBottom: "18px"

  },



  uploadGrid: {

    display: "grid",

    gridTemplateColumns:

      "repeat(auto-fit, minmax(220px,1fr))",

    gap: "12px"

  },



  field: {

    display: "flex",

    flexDirection: "column",

    gap: "6px",

    marginBottom: "12px"

  },



  label: {

    color: "#344054",

    fontSize: "12px",

    fontWeight: "700"

  },



  input: {

    minHeight: "42px",

    border: "1px solid #D0D5DD",

    borderRadius: "9px",

    padding: "9px 11px",

    background: "#FFFFFF",

    boxSizing: "border-box"

  },



  uploadActions: {

    display: "flex",

    justifyContent: "flex-end"

  },



  documentsList: {

    display: "flex",

    flexDirection: "column",

    gap: "8px"

  },



  documentRow: {

    display: "flex",

    alignItems: "center",

    gap: "12px",

    padding: "12px 14px",

    border: "1px solid #E4E7EC",

    borderRadius: "10px",

    background: "#FCFCFD"

  },



  documentIcon: {

    width: "40px",

    height: "40px",

    minWidth: "40px",

    borderRadius: "9px",

    background: "#EEF4FF",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    fontSize: "19px"

  },



  documentInfo: {

    flex: 1,

    minWidth: 0

  },



  documentName: {

    fontWeight: "800",

    color: "#344054",

    wordBreak: "break-word"

  },



  documentMeta: {

    marginTop: "3px",

    color: "#667085",

    fontSize: "11px"

  },



  documentDescription: {

    marginTop: "4px",

    color: "#667085",

    fontSize: "12px"

  },



  viewDocumentButton: {

    textDecoration: "none",

    color: "#2167D5",

    border: "1px solid #BFD3F6",

    background: "#EEF4FF",

    borderRadius: "8px",

    padding: "8px 11px",

    fontWeight: "700",

    fontSize: "12px",

    whiteSpace: "nowrap"

  },



  emptyDocuments: {

    textAlign: "center",

    padding: "25px",

    background: "#F8FAFC",

    borderRadius: "12px",

    color: "#667085"

  },



  emptyDocumentIcon: {

    fontSize: "32px",

    marginBottom: "7px"

  },



  smallEmpty: {

    padding: "14px",

    background: "#F8FAFC",

    borderRadius: "10px",

    color: "#667085",

    fontSize: "13px"

  },





  // ==================================================

  // MÓDULOS

  // ==================================================



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