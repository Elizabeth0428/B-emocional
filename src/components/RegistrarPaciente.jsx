import React, {
  useMemo,
  useState
} from "react";

import {
  getToken,
  getCurrentUser
} from "../services/AuthService";

import HistorialForm from "./HistorialForm.jsx";


const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;


// ==================================================
// CALCULAR EDAD
// ==================================================

const calcularEdad =
  fecha => {

    if (!fecha) {
      return "";
    }


    const nacimiento =
      new Date(
        `${fecha}T00:00:00`
      );


    const hoy =
      new Date();


    if (
      Number.isNaN(
        nacimiento.getTime()
      )
    ) {
      return "";
    }


    let edad =
      hoy.getFullYear() -
      nacimiento.getFullYear();


    const mes =
      hoy.getMonth() -
      nacimiento.getMonth();


    if (
      mes < 0 ||
      (
        mes === 0 &&
        hoy.getDate() <
        nacimiento.getDate()
      )
    ) {

      edad--;

    }


    return edad >= 0
      ? String(edad)
      : "";

  };


// ==================================================
// COMPONENTE
// ==================================================

const RegistrarPaciente = ({

  onBack,

  datosIniciales = null,

  idCanalizacion = null,

  desdeCanalizacion = false,

  onComplete

}) => {

  const user =
    getCurrentUser();


  const inicial =
    useMemo(
      () => ({

        nombre:
          datosIniciales?.nombre ||
          "",

        sexo:
          "",

        fecha_nacimiento:
          "",

        edad:
          "",

        correo:
          datosIniciales?.correo ||
          "",

        telefono:
          datosIniciales?.telefono ||
          "",

        direccion:
          "",

        antecedentes:
          "",

        id_psicologo:
          user?.id_psicologo ||
          null

      }),
      [
        datosIniciales,
        user?.id_psicologo
      ]
    );


  const [
    formData,
    setFormData
  ] =
    useState(inicial);


  const [
    nuevoPaciente,
    setNuevoPaciente
  ] =
    useState(null);


  const [
    guardando,
    setGuardando
  ] =
    useState(false);


  const [
    error,
    setError
  ] =
    useState("");


  // ==================================================
  // CAMBIAR CAMPOS
  // ==================================================

  const handleChange =
    e => {

      const {
        name,
        value
      } =
        e.target;


      if (
        name ===
        "fecha_nacimiento"
      ) {

        setFormData(
          anterior => ({

            ...anterior,

            fecha_nacimiento:
              value,

            edad:
              calcularEdad(
                value
              )

          })
        );


        return;

      }


      setFormData(
        anterior => ({

          ...anterior,

          [name]:
            value

        })
      );

    };


  // ==================================================
  // GUARDAR PACIENTE
  // ==================================================

  const handleSubmit =
    async () => {

      if (
        !formData.nombre
          .trim() ||

        !formData.sexo ||

        !formData
          .fecha_nacimiento
      ) {

        setError(
          "Debes llenar nombre, sexo y fecha de nacimiento."
        );

        return;

      }


      try {

        setGuardando(
          true
        );

        setError("");


        const token =
          getToken();


        const payload = {

          ...formData

        };


        if (
          desdeCanalizacion &&
          idCanalizacion
        ) {

          payload
            .desde_canalizacion =
            true;


          payload
            .id_canalizacion =
            idCanalizacion;

        }


        const respuesta =
          await fetch(
            `${API_URL}/api/pacientes`,
            {

              method:
                "POST",

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
            "No fue posible registrar al paciente."
          );

        }


        if (
          !data?.id_paciente
        ) {

          throw new Error(
            "El servidor no devolvió el expediente del paciente."
          );

        }


        setNuevoPaciente({

          id_paciente:
            data.id_paciente,

          nombre:
            formData.nombre
              .trim(),

          reutilizado:
            Boolean(
              data.reutilizado
            )

        });


      } catch (
        err
      ) {

        console.error(
          "❌ Error registrando paciente:",
          err
        );


        setError(
          err?.message ||
          "No fue posible registrar al paciente."
        );


      } finally {

        setGuardando(
          false
        );

      }

    };


  // ==================================================
  // HISTORIAL CLÍNICO
  // ==================================================

  if (
    nuevoPaciente
  ) {

    return (

      <HistorialForm

        paciente={
          nuevoPaciente
        }

        onBack={
          () => {

            if (
              onComplete
            ) {

              onComplete(
                nuevoPaciente
              );

            }

            else if (
              onBack
            ) {

              onBack();

            }

          }
        }

        onSave={
          () => {

            if (
              onComplete
            ) {

              onComplete(
                nuevoPaciente
              );

            }

            else if (
              onBack
            ) {

              onBack();

            }

          }
        }

      />

    );

  }


  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div style={styles.page}>

      <div style={styles.card}>

        {/* CABECERA */}

        <div style={styles.header}>

          <div>

            <div style={styles.icon}>
              👤
            </div>


            <h2 style={styles.title}>

              {
                desdeCanalizacion
                  ? "Completar datos del paciente"
                  : "Registrar nuevo paciente"
              }

            </h2>


            <p style={styles.subtitle}>

              {
                desdeCanalizacion
                  ? "Completa los datos necesarios antes de iniciar el expediente clínico."
                  : "Captura la información general del nuevo paciente."
              }

            </p>

          </div>


          {onBack && (

            <button

              type="button"

              style={styles.closeButton}

              onClick={
                onBack
              }

              disabled={
                guardando
              }

            >
              ×
            </button>

          )}

        </div>


        {/* AVISO */}

        {desdeCanalizacion && (

          <div style={styles.notice}>

            <span style={styles.noticeIcon}>
              🔐
            </span>

            <div>

              <strong>
                Alta desde canalización
              </strong>

              <p style={styles.noticeText}>
                El teléfono y correo ya fueron
                proporcionados después de aceptar
                la canalización. Completa únicamente
                la información clínica necesaria.
              </p>

            </div>

          </div>

        )}


        {/* ERROR */}

        {error && (

          <div style={styles.error}>
            ⚠️ {error}
          </div>

        )}


        {/* FORMULARIO */}

        <div style={styles.grid}>


          <Campo
            label="Nombre completo *"
            full
          >

            <input
              type="text"
              name="nombre"
              value={
                formData.nombre
              }
              onChange={
                handleChange
              }
              placeholder="Nombre completo"
              style={styles.input}
            />

          </Campo>


          <Campo label="Sexo *">

            <select
              name="sexo"
              value={
                formData.sexo
              }
              onChange={
                handleChange
              }
              style={styles.input}
            >

              <option value="">
                Selecciona sexo
              </option>

              <option value="M">
                Masculino
              </option>

              <option value="F">
                Femenino
              </option>

              <option value="X">
                Otro
              </option>

            </select>

          </Campo>


          <Campo label="Fecha de nacimiento *">

            <input
              type="date"
              name="fecha_nacimiento"
              value={
                formData
                  .fecha_nacimiento
              }
              onChange={
                handleChange
              }
              style={styles.input}
            />

          </Campo>


          <Campo label="Edad">

            <input
              type="number"
              name="edad"
              value={
                formData.edad
              }
              readOnly
              style={{
                ...styles.input,
                ...styles.readOnly
              }}
            />

          </Campo>


          <Campo label="Teléfono">

            <input
              type="text"
              name="telefono"
              value={
                formData.telefono
              }
              onChange={
                handleChange
              }
              placeholder="Teléfono"
              style={styles.input}
            />

          </Campo>


          <Campo
            label="Correo electrónico"
            full
          >

            <input
              type="email"
              name="correo"
              value={
                formData.correo
              }
              onChange={
                handleChange
              }
              placeholder="Correo electrónico"
              style={styles.input}
            />

          </Campo>


          <Campo
            label="Dirección"
            full
          >

            <input
              type="text"
              name="direccion"
              value={
                formData.direccion
              }
              onChange={
                handleChange
              }
              placeholder="Dirección"
              style={styles.input}
            />

          </Campo>


          <Campo
            label="Antecedentes relevantes"
            full
          >

            <textarea
              name="antecedentes"
              value={
                formData
                  .antecedentes
              }
              onChange={
                handleChange
              }
              placeholder="Antecedentes relevantes"
              style={styles.textarea}
            />

          </Campo>

        </div>


        {/* BOTONES */}

        <div style={styles.actions}>

          <button
            type="button"
            style={styles.cancelButton}
            onClick={
              onBack
            }
            disabled={
              guardando
            }
          >
            Cancelar
          </button>


          <button
            type="button"
            style={styles.saveButton}
            onClick={
              handleSubmit
            }
            disabled={
              guardando
            }
          >

            {
              guardando
                ? "Guardando..."
                : "Guardar y continuar →"
            }

          </button>

        </div>

      </div>

    </div>

  );

};


// ==================================================
// CAMPO
// ==================================================

const Campo = ({
  label,
  children,
  full = false
}) => (

  <div
    style={
      full
        ? styles.full
        : undefined
    }
  >

    <label style={styles.label}>
      {label}
    </label>

    {children}

  </div>

);


// ==================================================
// ESTILOS COMPACTOS
// ==================================================

const styles = {

  page:{
    width:"100%",
    boxSizing:"border-box"
  },

  card:{
    background:"#FFFFFF",
    border:"1px solid #E0E8F4",
    borderRadius:22,
    padding:28,
    maxWidth:850,
    margin:"0 auto",
    boxShadow:"0 10px 30px rgba(40,80,140,.10)",
    boxSizing:"border-box"
  },

  header:{
    display:"flex",
    justifyContent:"space-between",
    alignItems:"flex-start",
    gap:20,
    paddingBottom:20,
    marginBottom:20,
    borderBottom:"1px solid #EDF1F7"
  },

  icon:{
    width:52,
    height:52,
    display:"flex",
    alignItems:"center",
    justifyContent:"center",
    background:"#EEF4FF",
    borderRadius:15,
    fontSize:25,
    marginBottom:12
  },

  title:{
    margin:"0 0 7px",
    color:"#203F6F",
    fontSize:27
  },

  subtitle:{
    margin:0,
    color:"#6B7890",
    lineHeight:1.55
  },

  closeButton:{
    border:"none",
    width:38,
    height:38,
    borderRadius:"50%",
    background:"#F1F4F8",
    color:"#52647D",
    cursor:"pointer",
    fontSize:24
  },

  notice:{
    display:"flex",
    gap:13,
    padding:16,
    marginBottom:20,
    background:"#EFF7FF",
    border:"1px solid #CCE4FB",
    borderRadius:15,
    color:"#405D7D"
  },

  noticeIcon:{
    fontSize:22
  },

  noticeText:{
    margin:"5px 0 0",
    lineHeight:1.5,
    color:"#607893"
  },

  error:{
    padding:"13px 16px",
    marginBottom:18,
    background:"#FFF0F0",
    border:"1px solid #F4C4C4",
    color:"#A93636",
    borderRadius:13,
    fontWeight:600
  },

  grid:{
    display:"grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(240px,1fr))",
    gap:"16px 18px"
  },

  full:{
    gridColumn:"1 / -1"
  },

  label:{
    display:"block",
    marginBottom:7,
    color:"#61718A",
    fontSize:13,
    fontWeight:700
  },

  input:{
    width:"100%",
    minHeight:46,
    padding:"10px 12px",
    border:"1px solid #CBD7E6",
    borderRadius:11,
    background:"#FFFFFF",
    color:"#314968",
    fontSize:14,
    outline:"none",
    boxSizing:"border-box"
  },

  readOnly:{
    background:"#F5F7FA",
    color:"#72809A"
  },

  textarea:{
    width:"100%",
    minHeight:100,
    padding:12,
    border:"1px solid #CBD7E6",
    borderRadius:11,
    background:"#FFFFFF",
    color:"#314968",
    fontSize:14,
    fontFamily:"inherit",
    resize:"vertical",
    outline:"none",
    boxSizing:"border-box"
  },

  actions:{
    display:"flex",
    justifyContent:"flex-end",
    gap:12,
    flexWrap:"wrap",
    marginTop:26,
    paddingTop:20,
    borderTop:"1px solid #EDF1F7"
  },

  cancelButton:{
    padding:"12px 20px",
    border:"1px solid #C8D3E1",
    borderRadius:12,
    background:"#FFFFFF",
    color:"#586A83",
    cursor:"pointer",
    fontWeight:700
  },

  saveButton:{
    padding:"12px 22px",
    border:"none",
    borderRadius:12,
    background:"#1F7A4D",
    color:"#FFFFFF",
    cursor:"pointer",
    fontWeight:700,
    boxShadow:"0 5px 14px rgba(31,122,77,.20)"
  }

};


export default RegistrarPaciente;