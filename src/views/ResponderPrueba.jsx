// src/views/ResponderPrueba.jsx

import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

export default function ResponderPrueba() {

  // ==================================================
  // ID DE LA HABILITACIÓN
  // ==================================================

  const { idHabilitacion } = useParams();

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
        console.log("🔗 ID habilitación recibido:", idHabilitacion);

        if (!idHabilitacion) {
          console.error("❌ No se recibió idHabilitacion en la URL");
          return;
        }

        const res = await fetch(
          `https://reflejoyalma.com/api/evaluation/pruebas/habilitacion/${idHabilitacion}`
        );

        if (!res.ok) {
          throw new Error("No se pudo cargar la prueba");
        }

        const data = await res.json();
        console.log("✅ Prueba recibida:", data);
        setPrueba(data);

      } catch (err) {
        console.error("❌ Error al obtener prueba:", err);
      }
    };

    fetchData();
  }, [idHabilitacion]);

  // ==================================================
  // GUARDAR RESPUESTA SELECCIONADA
  // ==================================================

  const handleRespuesta = (idPregunta, idOpcion) => {
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
      if (!prueba) return;

      if (!prueba.preguntas || prueba.preguntas.length === 0) {
        alert("❌ Esta prueba no tiene preguntas.");
        return;
      }

      const cantidadPreguntas = prueba.preguntas.length;
      const cantidadRespuestas = Object.keys(respuestas).length;

      if (cantidadRespuestas < cantidadPreguntas) {
        alert("⚠️ Debes responder todas las preguntas antes de enviar la prueba.");
        return;
      }

      const values = Object.entries(respuestas).map(([id_pregunta, id_opcion]) => ({
        id_paciente: prueba.id_paciente,
        id_prueba: prueba.id_prueba,
        id_pregunta,
        id_opcion
      }));

      console.log("📤 Respuestas a enviar:", values);

      // GUARDAR RESPUESTAS
      const resRespuestas = await fetch(
        "https://reflejoyalma.com/api/evaluation/respuestas/publico",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            id_habilitacion: prueba.id_habilitacion,
            respuestas: values
          })
        }
      );

      if (!resRespuestas.ok) {
        throw new Error("No se pudieron guardar las respuestas");
      }
      console.log("✅ Respuestas guardadas");

      // FINALIZAR PRUEBA
      const resFinal = await fetch(
        `https://reflejoyalma.com/api/evaluation/pruebas/${prueba.id_prueba}/finalizar/publico`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            id_paciente: prueba.id_paciente,
            id_habilitacion: prueba.id_habilitacion
          })
        }
      );

      if (!resFinal.ok) {
        throw new Error("No se pudo finalizar la prueba");
      }

      const dataFinal = await resFinal.json();
      console.log("✅ Resultado final:", dataFinal);
      setFinalizado(dataFinal);

    } catch (err) {
      console.error("❌ Error al enviar respuestas:", err);
      alert("❌ No se pudieron enviar las respuestas");
    }
  };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (!prueba) {
    return (
      <div style={loadingContainer}>
        <div style={loadingIcon}>🧪</div>
        <p style={loadingText}>⏳ Cargando prueba...</p>
      </div>
    );
  }

  // ==================================================
  // RESULTADO FINAL (Vista segura para el paciente)
  // ==================================================

  if (finalizado) {
    return (
      <div style={container}>
        <div style={{ textAlign: "center", padding: "35px 20px" }}>
          <div style={{ fontSize: "58px", marginBottom: "15px" }}>✅</div>
          <h2 style={{ color: "#2E7D32", marginBottom: "12px" }}>
            Prueba enviada correctamente
          </h2>
          <p style={{ color: "#455A64", fontSize: "17px", lineHeight: "1.6", margin: "0 auto 8px", maxWidth: "520px" }}>
            Tus respuestas han sido registradas correctamente.
          </p>
          <p style={{ color: "#78909C", fontSize: "15px", margin: 0 }}>
            Ya puedes cerrar esta ventana.
          </p>
        </div>
      </div>
    );
  }

  // ==================================================
  // VISTA DE PREGUNTAS
  // ==================================================

  return (
    <div style={container}>
      <h2 style={{ textAlign: "center", color: "#0D47A1", marginBottom: "10px" }}>
        🧪 {prueba.nombre}
      </h2>
      <p style={{ textAlign: "center", marginBottom: "25px", color: "#555" }}>
        {prueba.descripcion || "Responde las siguientes preguntas."}
      </p>

      {prueba.preguntas?.map((p, index) => (
        <div key={`preg-${p.id_pregunta}`} style={preguntaBox}>
          <p style={{ fontWeight: "600", marginBottom: "12px", color: "#333" }}>
            {index + 1}. {p.texto}
          </p>
          {p.opciones?.map((o) => (
            <label
              key={`op-${p.id_pregunta}-${o.id_opcion}`}
              style={{
                display: "flex", alignItems: "center", marginBottom: "8px", cursor: "pointer",
                padding: "6px 10px", borderRadius: "6px", transition: "background 0.2s"
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "#f0f4ff"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            >
              <input
                type="radio"
                name={`preg_${p.id_pregunta}`}
                value={o.id_opcion}
                checked={respuestas[p.id_pregunta] === o.id_opcion}
                onChange={() => handleRespuesta(p.id_pregunta, o.id_opcion)}
                style={{ marginRight: "10px" }}
              />
              {o.texto}
            </label>
          ))}
        </div>
      ))}

      <div style={{ textAlign: "center", marginTop: "25px" }}>
        <button
          style={btnEnviar}
          onMouseEnter={(e) => (e.currentTarget.style.background = "#1565C0")}
          onMouseLeave={(e) => (e.currentTarget.style.background = "#1976D2")}
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
  maxWidth: "750px", margin: "80px auto", padding: "40px",
  textAlign: "center", fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif"
};

const loadingIcon = { fontSize: "50px", marginBottom: "15px" };
const loadingText = { color: "#607D8B", fontSize: "17px" };

const container = {
  maxWidth: "750px", margin: "30px auto", padding: "30px", background: "#ffffff",
  borderRadius: "16px", boxShadow: "0 6px 20px rgba(0,0,0,0.12)",
  fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif", color: "#212121"
};

const preguntaBox = {
  marginBottom: "25px", padding: "18px", background: "#f9f9f9",
  borderRadius: "12px", boxShadow: "0 3px 8px rgba(0,0,0,0.08)"
};

const btnEnviar = {
  background: "#1976D2", color: "white", border: "none", padding: "14px 26px",
  borderRadius: "10px", cursor: "pointer", fontWeight: "600", fontSize: "16px",
  transition: "all 0.3s ease", boxShadow: "0 4px 12px rgba(25,118,210,0.4)"
};