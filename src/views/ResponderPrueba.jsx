// src/views/ResponderPrueba.jsx

import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";

export default function ResponderPrueba() {

  // ==================================================
  // ID DE LA HABILITACIÓN
  // ==================================================

  const { idHabilitacion } = useParams();

  const navigate = useNavigate();


  // ==================================================
  // ESTADOS
  // ==================================================

  const [prueba, setPrueba] = useState(null);

  const [respuestas, setRespuestas] = useState({});

  const [finalizado, setFinalizado] = useState(null);


  // ==================================================
  // CARGAR PRUEBA + PREGUNTAS
  // ==================================================

  useEffect(() => {

    const fetchData = async () => {

      try {

        console.log(
          "🔗 ID habilitación recibido:",
          idHabilitacion
        );


        // ----------------------------------------------
        // Validar ID
        // ----------------------------------------------

        if (!idHabilitacion) {

          console.error(
            "❌ No se recibió idHabilitacion en la URL"
          );

          return;

        }


        // ----------------------------------------------
        // Obtener prueba
        // ----------------------------------------------

       const res = await fetch(
  `https://reflejoyalma.com/api/evaluation/pruebas/habilitacion/${idHabilitacion}`
);


        if (!res.ok) {

          throw new Error(
            "No se pudo cargar la prueba"
          );

        }


        const data = await res.json();


        console.log(
          "✅ Prueba recibida:",
          data
        );


        setPrueba(data);


      } catch (err) {

        console.error(
          "❌ Error al obtener prueba:",
          err
        );

      }

    };


    fetchData();

  }, [idHabilitacion]);


  // ==================================================
  // GUARDAR RESPUESTA SELECCIONADA
  // ==================================================

  const handleRespuesta = (
    idPregunta,
    idOpcion
  ) => {

    setRespuestas((prev) => ({

      ...prev,

      [idPregunta]: idOpcion

    }));

  };


  // ==================================================
// ENVIAR RESPUESTAS
// ==================================================

const handleEnviar = async () => {

  try {

    if (!prueba) {
      return;
    }


    // ----------------------------------------------
    // Verificar que haya respuestas
    // ----------------------------------------------

    if (
      !prueba.preguntas ||
      prueba.preguntas.length === 0
    ) {

      alert(
        "❌ Esta prueba no tiene preguntas."
      );

      return;

    }


    // ----------------------------------------------
    // Verificar respuestas completas
    // ----------------------------------------------

    const cantidadPreguntas =
      prueba.preguntas.length;

    const cantidadRespuestas =
      Object.keys(respuestas).length;


    if (
      cantidadRespuestas <
      cantidadPreguntas
    ) {

      alert(
        "⚠️ Debes responder todas las preguntas antes de enviar la prueba."
      );

      return;

    }


    // ----------------------------------------------
    // Formatear respuestas
    // ----------------------------------------------

    const values =
      Object.entries(respuestas).map(
        ([id_pregunta, id_opcion]) => ({

          id_paciente:
            prueba.id_paciente,

          id_prueba:
            prueba.id_prueba,

          id_pregunta,

          id_opcion

        })
      );


    console.log(
      "📤 Respuestas a enviar:",
      values
    );


    // ==================================================
    // GUARDAR RESPUESTAS
    // ==================================================

    const resRespuestas =
      await fetch(
        "https://reflejoyalma.com/api/evaluation/respuestas/publico",
        {

          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({

            id_habilitacion:
              prueba.id_habilitacion,

            respuestas:
              values

          })

        }
      );


    if (!resRespuestas.ok) {

      throw new Error(
        "No se pudieron guardar las respuestas"
      );

    }


    console.log(
      "✅ Respuestas guardadas"
    );


    // ==================================================
    // FINALIZAR PRUEBA
    // ==================================================

    const resFinal =
      await fetch(

        `https://reflejoyalma.com/api/evaluation/pruebas/${prueba.id_prueba}/finalizar/publico`,

        {

          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({

            id_paciente:
              prueba.id_paciente,

            id_habilitacion:
              prueba.id_habilitacion

          })

        }

      );


    if (!resFinal.ok) {

      throw new Error(
        "No se pudo finalizar la prueba"
      );

    }


    const dataFinal =
      await resFinal.json();


    console.log(
      "✅ Resultado final:",
      dataFinal
    );


    setFinalizado(
      dataFinal
    );


  } catch (err) {

    console.error(
      "❌ Error al enviar respuestas:",
      err
    );


    alert(
      "❌ No se pudieron enviar las respuestas"
    );

  }

};


  // ==================================================
  // CARGANDO
  // ==================================================

  if (!prueba) {

    return (

      <div style={loadingContainer}>

        <div style={loadingIcon}>
          🧪
        </div>

        <p style={loadingText}>
          ⏳ Cargando prueba...
        </p>

      </div>

    );

  }


  // ==================================================
  // RESULTADO FINAL
  // ==================================================

  if (finalizado) {

    return (

      <div style={container}>

        <h2
          style={{
            color: "#2E7D32",
            textAlign: "center",
            marginBottom: "20px"
          }}
        >
          ✅ Prueba finalizada
        </h2>


        <div style={resultadoBox}>

          <p>
            <b>
              Puntaje total:
            </b>{" "}

            {
              finalizado.puntaje_total
            }

          </p>


          <p>
            <b>
              Interpretación:
            </b>{" "}

            {
              finalizado.interpretacion
            }

          </p>

        </div>


        {/* ==========================================
            VOLVER
        ========================================== */}

        <div
          style={{
            textAlign: "center",
            marginTop: "30px"
          }}
        >

          <button
            style={btnVolver}
            onClick={() =>
              navigate("/dashboard")
            }
          >

            ⬅ Volver al Dashboard

          </button>

        </div>

      </div>

    );

  }


  // ==================================================
  // VISTA DE PREGUNTAS
  // ==================================================

  return (

    <div style={container}>

      {/* ============================================
          ENCABEZADO
      ============================================ */}

      <h2
        style={{
          textAlign: "center",
          color: "#0D47A1",
          marginBottom: "10px"
        }}
      >

        🧪 {prueba.nombre}

      </h2>


      <p
        style={{
          textAlign: "center",
          marginBottom: "25px",
          color: "#555"
        }}
      >

        {
          prueba.descripcion ||
          "Responde las siguientes preguntas."
        }

      </p>


      {/* ============================================
          PREGUNTAS
      ============================================ */}

      {prueba.preguntas?.map(
        (p, index) => (

          <div
            key={`preg-${p.id_pregunta}`}
            style={preguntaBox}
          >

            <p
              style={{
                fontWeight: "600",
                marginBottom: "12px",
                color: "#333"
              }}
            >

              {index + 1}. {p.texto}

            </p>


            {/* ======================================
                OPCIONES
            ====================================== */}

            {p.opciones?.map(
              (o) => (

                <label
                  key={
                    `op-${p.id_pregunta}-${o.id_opcion}`
                  }

                  style={{
                    display: "flex",
                    alignItems: "center",
                    marginBottom: "8px",
                    cursor: "pointer",
                    padding: "6px 10px",
                    borderRadius: "6px",
                    transition:
                      "background 0.2s"
                  }}

                  onMouseEnter={(e) => {

                    e.currentTarget.style.background =
                      "#f0f4ff";

                  }}

                  onMouseLeave={(e) => {

                    e.currentTarget.style.background =
                      "transparent";

                  }}
                >

                  <input
                    type="radio"

                    name={
                      `preg_${p.id_pregunta}`
                    }

                    value={
                      o.id_opcion
                    }

                    checked={
                      respuestas[
                        p.id_pregunta
                      ] ===
                      o.id_opcion
                    }

                    onChange={() =>
                      handleRespuesta(
                        p.id_pregunta,
                        o.id_opcion
                      )
                    }

                    style={{
                      marginRight: "10px"
                    }}
                  />


                  {o.texto}

                </label>

              )
            )}

          </div>

        )
      )}


      {/* ============================================
          BOTÓN ENVIAR
      ============================================ */}

      <div
        style={{
          textAlign: "center",
          marginTop: "25px"
        }}
      >

        <button
          style={btnEnviar}

          onMouseEnter={(e) =>
            (
              e.currentTarget.style.background =
                "#1565C0"
            )
          }

          onMouseLeave={(e) =>
            (
              e.currentTarget.style.background =
                "#1976D2"
            )
          }

          onClick={handleEnviar}
        >

          📤 Enviar respuestas

        </button>

      </div>

    </div>

  );

}


// =====================================================
// 🎨 ESTILOS
// =====================================================

const loadingContainer = {

  maxWidth: "750px",

  margin: "80px auto",

  padding: "40px",

  textAlign: "center",

  fontFamily:
    "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif"

};


const loadingIcon = {

  fontSize: "50px",

  marginBottom: "15px"

};


const loadingText = {

  color: "#607D8B",

  fontSize: "17px"

};


const container = {

  maxWidth: "750px",

  margin: "30px auto",

  padding: "30px",

  background: "#ffffff",

  borderRadius: "16px",

  boxShadow:
    "0 6px 20px rgba(0,0,0,0.12)",

  fontFamily:
    "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",

  color: "#212121"

};


const preguntaBox = {

  marginBottom: "25px",

  padding: "18px",

  background: "#f9f9f9",

  borderRadius: "12px",

  boxShadow:
    "0 3px 8px rgba(0,0,0,0.08)"

};


const resultadoBox = {

  padding: "20px",

  background: "#E8F5E9",

  border:
    "1px solid #A5D6A7",

  borderRadius: "10px",

  color: "#1B5E20",

  fontSize: "16px",

  fontWeight: "500",

  textAlign: "center"

};


const btnEnviar = {

  background: "#1976D2",

  color: "white",

  border: "none",

  padding: "14px 26px",

  borderRadius: "10px",

  cursor: "pointer",

  fontWeight: "600",

  fontSize: "16px",

  transition:
    "all 0.3s ease",

  boxShadow:
    "0 4px 12px rgba(25,118,210,0.4)"

};


const btnVolver = {

  background: "#43A047",

  color: "white",

  border: "none",

  padding: "12px 24px",

  borderRadius: "10px",

  cursor: "pointer",

  fontWeight: "600",

  fontSize: "16px",

  transition:
    "all 0.3s ease",

  boxShadow:
    "0 4px 12px rgba(67,160,71,0.4)"

};