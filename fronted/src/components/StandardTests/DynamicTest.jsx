// src/components/StandardTests/DynamicTest.jsx
import React, { useEffect, useState } from "react";
import axios from "axios";

// 🚀 API de producción
const API_URL = import.meta.env.VITE_API_URL;

const DynamicTest = ({ idPrueba, idSesion, token, onFinish }) => {
  const [preguntas, setPreguntas] = useState([]);
  const [index, setIndex] = useState(0);
  const [respuestas, setRespuestas] = useState({});
  const [loading, setLoading] = useState(true);
  const [confirmarEnvio, setConfirmarEnvio] = useState(false);

  useEffect(() => {
    const fetchPreguntas = async () => {
      try {
        const res = await axios.get(
          `${API_URL}/api/pruebas/${idPrueba}/preguntas`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        setPreguntas(res.data);
      } catch (err) {
        console.error("❌ Error al cargar preguntas:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchPreguntas();
  }, [idPrueba, token]);

  const handleRespuesta = (idPregunta, opcion, puntaje) => {
    setRespuestas((prev) => ({
      ...prev,
      [idPregunta]: { respuesta: opcion, puntaje_obtenido: puntaje },
    }));

    if (index + 1 < preguntas.length) {
      setIndex(index + 1);
    }
  };

  const handleSubmit = async () => {
    if (!idSesion) {
      alert("⚠️ No hay sesión activa para guardar esta prueba.");
      return;
    }

    try {
      const respuestasArray = Object.keys(respuestas).map((idPregunta) => ({
        id_pregunta: parseInt(idPregunta),
        respuesta: respuestas[idPregunta].respuesta,
        puntaje_obtenido: respuestas[idPregunta].puntaje_obtenido,
      }));

      await axios.post(
        `${API_URL}/api/respuestas`,
        { id_prueba: idPrueba, id_sesion: idSesion, respuestas: respuestasArray },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const result = await axios.post(
        `${API_URL}/api/pruebas/${idPrueba}/finalizar`,
        { id_sesion: idSesion },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setIndex(0);
      setRespuestas({});
      setConfirmarEnvio(false);

      if (onFinish) onFinish(result.data);
    } catch (err) {
      console.error("❌ Error al enviar respuestas:", err);
      alert("⚠️ Error al guardar respuestas. Intenta de nuevo.");
    }
  };

  if (loading) return <p>Cargando preguntas...</p>;
  if (!preguntas.length) return <p>No hay preguntas disponibles.</p>;

  const pregunta = preguntas[index];
  let opciones = [];
  let puntajes = [];

  try {
    opciones = JSON.parse(pregunta.opciones || "[]");
    puntajes = JSON.parse(pregunta.puntajes || "[]");
  } catch (err) {
    console.error("❌ Error parseando opciones/puntajes:", err);
  }

  const todasRespondidas = preguntas.every(
    (p) => respuestas[p.id_pregunta]
  );

  return (
    <div style={{ textAlign: "center", padding: "20px" }}>
      {!confirmarEnvio ? (
        <>
          <h3>
            Pregunta {index + 1} de {preguntas.length}
          </h3>
          <p>{pregunta.enunciado}</p>

          {opciones.map((opcion, idx) => (
            <button
              key={idx}
              onClick={() =>
                handleRespuesta(pregunta.id_pregunta, opcion, puntajes[idx])
              }
              style={{
                display: "block",
                margin: "12px auto",
                padding: "12px 18px",
                borderRadius: "10px",
                background: "#29B6F6",
                color: "#fff",
                border: "none",
              }}
            >
              {opcion}
            </button>
          ))}

          {index === preguntas.length - 1 && (
            <button
              onClick={() => setConfirmarEnvio(true)}
              disabled={!todasRespondidas}
              style={{
                marginTop: "20px",
                padding: "12px 20px",
                borderRadius: "10px",
                backgroundColor: todasRespondidas ? "#43A047" : "#9E9E9E",
                color: "#fff",
                border: "none",
              }}
            >
              ✅ Finalizar prueba
            </button>
          )}
        </>
      ) : (
        <div>
          <h3>¿Confirmas el envío de la prueba?</h3>
          <button onClick={handleSubmit}>✅ Sí, enviar</button>
          <button onClick={() => setConfirmarEnvio(false)}>❌ Cancelar</button>
        </div>
      )}
    </div>
  );
};

export default DynamicTest;
