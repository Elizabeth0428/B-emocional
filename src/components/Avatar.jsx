// src/components/Avatar.jsx
import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";

const mensajes = [
  "💡 Recuerda actualizar los historiales clínicos.",
  "📊 Puedes revisar el progreso de tus pacientes.",
  "🧠 Una prueba rápida puede ayudar mucho.",
  "📅 Organiza tus sesiones y revisa pendientes.",
  "😊 ¡Gran trabajo, sigue adelante!"
];

export default function Avatar() {
  const [mensaje, setMensaje] = useState(mensajes[0]);

  useEffect(() => {
    const interval = setInterval(() => {
      const randomMsg =
        mensajes[Math.floor(Math.random() * mensajes.length)];

      setMensaje(randomMsg);
    }, 6000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div style={styles.wrapper}>

      {/* =================================================
          DOCTORA
      ================================================= */}
      <motion.img
        src="/doctora-avatar.png"
        alt="Asistente Doctora"
        style={styles.avatar}
        animate={{
          y: [0, -8, 0],
        }}
        transition={{
          duration: 3.5,
          repeat: Infinity,
          ease: "easeInOut",
        }}
      />

      {/* =================================================
          BURBUJA
      ================================================= */}
      <motion.div
        style={styles.mensajeBox}
        initial={{
          opacity: 0,
          x: 15,
        }}
        animate={{
          opacity: 1,
          x: 0,
        }}
        transition={{
          duration: 0.8,
        }}
      >
        <div style={styles.titulo}>
          🧠 Asistente Doctora
        </div>

        <div style={styles.mensaje}>
          {mensaje}
        </div>

        {/* Punta de la burbuja */}
        <div style={styles.bubbleTail}></div>
      </motion.div>

    </div>
  );
}


/* ============================================================
   ESTILOS
============================================================ */

const styles = {

  /* =====================================================
     CONTENEDOR
  ===================================================== */

  wrapper: {
    position: "relative",

    width: "350px",
    height: "170px",

    display: "flex",
    alignItems: "center",
    justifyContent: "center",

    gap: "8px",

    zIndex: 50,

    boxSizing: "border-box",
  },


  /* =====================================================
     DOCTORA
  ===================================================== */

  avatar: {
    width: "145px",
    height: "auto",

    cursor: "pointer",

    display: "block",

    userSelect: "none",

    flexShrink: 0,

    zIndex: 51,
  },


  /* =====================================================
     BURBUJA
  ===================================================== */

  mensajeBox: {
    width: "190px",

    background:
      "linear-gradient(145deg, #FFFFFF, #F5FAFF)",

    padding: "11px 14px",

    borderRadius: "16px",

    boxShadow:
      "0 6px 18px rgba(40,80,140,0.14)",

    border: "1px solid #E3ECF7",

    boxSizing: "border-box",

    position: "relative",

    textAlign: "left",

    zIndex: 52,
  },


  /* =====================================================
     TÍTULO
  ===================================================== */

  titulo: {
    color: "#1759B7",

    fontSize: "12px",

    fontWeight: "800",

    marginBottom: "5px",
  },


  /* =====================================================
     MENSAJE
  ===================================================== */

  mensaje: {
    color: "#40566F",

    fontSize: "12px",

    lineHeight: "1.35",

    fontStyle: "italic",
  },


  /* =====================================================
     PUNTA
  ===================================================== */

  bubbleTail: {
    position: "absolute",

    left: "-10px",

    top: "50%",

    transform: "translateY(-50%)",

    width: "0",
    height: "0",

    borderTop: "8px solid transparent",
    borderBottom: "8px solid transparent",
    borderRight: "11px solid #FFFFFF",
  },
};