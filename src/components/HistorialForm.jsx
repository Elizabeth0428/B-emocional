import React, {
  useState
} from "react";

import {
  getToken
} from "../services/AuthService";


const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;


// ==================================================
// COMPONENTE
// ==================================================

const HistorialForm = ({
  paciente,
  onBack,
  onSave
}) => {

  const [
    formData,
    setFormData
  ] =
    useState({

      estado_civil: "",
      ocupacion: "",
      escolaridad: "",

      antecedentes_personales: "",
      antecedentes_familiares: "",
      antecedentes_patologicos: "",
      antecedentes_emocionales: "",

      habitos: "",
      alergias: "",
      enfermedades_previas: "",
      medicamentos_actuales: "",
      cirugias: "",

      historia_desarrollo: "",
      evaluacion_inicial: "",
      diagnostico_inicial: "",
      tratamiento_inicial: "",

      notas: ""

    });


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
  // CAMBIAR
  // ==================================================

  const handleChange =
    e => {

      const {
        name,
        value
      } =
        e.target;


      setFormData(
        anterior => ({

          ...anterior,

          [name]:
            value

        })
      );

    };


  // ==================================================
  // GUARDAR HISTORIAL
  // ==================================================

  const handleSubmit =
    async () => {

      if (
        !paciente?.id_paciente
      ) {

        setError(
          "No se puede guardar el historial sin un paciente válido."
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


        const respuesta =
          await fetch(
            `${API_URL}/api/historial-inicial`,
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
                JSON.stringify({

                  ...formData,

                  id_paciente:
                    paciente.id_paciente

                })

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
            "No fue posible guardar el historial."
          );

        }


        if (
          onSave
        ) {

          onSave(
            data
          );

        }


      } catch (
        err
      ) {

        console.error(
          "❌ Error guardando historial:",
          err
        );


        setError(
          err?.message ||
          "No se pudo guardar el historial clínico."
        );


      } finally {

        setGuardando(
          false
        );

      }

    };


  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div style={styles.card}>

      {/* CABECERA */}

      <div style={styles.header}>

        <div>

          <div style={styles.icon}>
            📋
          </div>


          <h2 style={styles.title}>
            Historial clínico inicial
          </h2>


          <p style={styles.subtitle}>

            Paciente:{" "}

            <strong style={styles.patientName}>
              {
                paciente?.nombre ||
                "Paciente"
              }
            </strong>

          </p>

        </div>

      </div>


      {error && (

        <div style={styles.error}>
          ⚠️ {error}
        </div>

      )}


      {/* DATOS GENERALES */}

      <SectionTitle>
        Datos generales
      </SectionTitle>


      <div style={styles.grid}>

        <Campo label="Estado civil">

          <input
            name="estado_civil"
            value={
              formData.estado_civil
            }
            onChange={
              handleChange
            }
            placeholder="Estado civil"
            style={styles.input}
          />

        </Campo>


        <Campo label="Ocupación">

          <input
            name="ocupacion"
            value={
              formData.ocupacion
            }
            onChange={
              handleChange
            }
            placeholder="Ocupación"
            style={styles.input}
          />

        </Campo>


        <Campo label="Escolaridad">

          <input
            name="escolaridad"
            value={
              formData.escolaridad
            }
            onChange={
              handleChange
            }
            placeholder="Escolaridad"
            style={styles.input}
          />

        </Campo>

      </div>


      {/* ANTECEDENTES */}

      <SectionTitle>
        Antecedentes
      </SectionTitle>


      <TextArea
        name="antecedentes_personales"
        label="Antecedentes personales"
        formData={formData}
        onChange={handleChange}
      />

      <TextArea
        name="antecedentes_familiares"
        label="Antecedentes familiares"
        formData={formData}
        onChange={handleChange}
      />

      <TextArea
        name="antecedentes_patologicos"
        label="Antecedentes patológicos"
        formData={formData}
        onChange={handleChange}
      />

      <TextArea
        name="antecedentes_emocionales"
        label="Antecedentes emocionales"
        formData={formData}
        onChange={handleChange}
      />


      {/* SALUD */}

      <SectionTitle>
        Salud y hábitos
      </SectionTitle>


      <div style={styles.twoColumns}>

        <TextArea
          name="habitos"
          label="Hábitos"
          formData={formData}
          onChange={handleChange}
        />

        <TextArea
          name="alergias"
          label="Alergias"
          formData={formData}
          onChange={handleChange}
        />

        <TextArea
          name="enfermedades_previas"
          label="Enfermedades previas"
          formData={formData}
          onChange={handleChange}
        />

        <TextArea
          name="medicamentos_actuales"
          label="Medicamentos actuales"
          formData={formData}
          onChange={handleChange}
        />

      </div>


      <TextArea
        name="cirugias"
        label="Cirugías"
        formData={formData}
        onChange={handleChange}
      />


      {/* EVALUACIÓN */}

      <SectionTitle>
        Evaluación clínica inicial
      </SectionTitle>


      <TextArea
        name="historia_desarrollo"
        label="Historia del desarrollo"
        formData={formData}
        onChange={handleChange}
      />

      <TextArea
        name="evaluacion_inicial"
        label="Evaluación inicial"
        formData={formData}
        onChange={handleChange}
      />

      <TextArea
        name="diagnostico_inicial"
        label="Diagnóstico inicial"
        formData={formData}
        onChange={handleChange}
      />

      <TextArea
        name="tratamiento_inicial"
        label="Tratamiento inicial"
        formData={formData}
        onChange={handleChange}
      />


      {/* NOTAS */}

      <SectionTitle>
        Notas adicionales
      </SectionTitle>


      <TextArea
        name="notas"
        label="Notas"
        formData={formData}
        onChange={handleChange}
      />


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
              : "💾 Guardar historial"
          }

        </button>

      </div>

    </div>

  );

};


// ==================================================
// COMPONENTES AUXILIARES
// ==================================================

const SectionTitle = ({
  children
}) => (

  <div style={styles.sectionTitle}>
    {children}
  </div>

);


const Campo = ({
  label,
  children
}) => (

  <div>

    <label style={styles.label}>
      {label}
    </label>

    {children}

  </div>

);


const TextArea = ({
  name,
  label,
  formData,
  onChange
}) => (

  <div style={styles.textBlock}>

    <label style={styles.label}>
      {label}
    </label>

    <textarea
      name={name}
      value={
        formData[name]
      }
      onChange={
        onChange
      }
      placeholder={label}
      style={styles.textarea}
    />

  </div>

);


// ==================================================
// ESTILOS COMPACTOS
// ==================================================

const styles = {

  card:{
    background:"#FFFFFF",
    border:"1px solid #E0E8F4",
    borderRadius:22,
    padding:28,
    maxWidth:900,
    margin:"0 auto",
    boxShadow:"0 10px 30px rgba(40,80,140,.10)",
    boxSizing:"border-box"
  },

  header:{
    paddingBottom:20,
    marginBottom:24,
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
    color:"#70809A"
  },

  patientName:{
    color:"#28764A"
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

  sectionTitle:{
    margin:"28px 0 14px",
    paddingBottom:8,
    borderBottom:"1px solid #E7EDF5",
    color:"#315A8F",
    fontSize:16,
    fontWeight:800
  },

  grid:{
    display:"grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(220px,1fr))",
    gap:16
  },

  twoColumns:{
    display:"grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(280px,1fr))",
    gap:16
  },

  textBlock:{
    marginBottom:14
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
    color:"#314968",
    fontSize:14,
    boxSizing:"border-box"
  },

  textarea:{
    width:"100%",
    minHeight:85,
    padding:12,
    border:"1px solid #CBD7E6",
    borderRadius:11,
    color:"#314968",
    fontSize:14,
    fontFamily:"inherit",
    resize:"vertical",
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


export default HistorialForm;