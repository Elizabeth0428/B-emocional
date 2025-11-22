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

  // 🔄 Cambiar mensajes cada 6s
  useEffect(() => {
    const interval = setInterval(() => {
      const randomMsg = mensajes[Math.floor(Math.random() * mensajes.length)];
      setMensaje(randomMsg);
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={styles.wrapper}>
      {/* Avatar flotante más grande */}
      <motion.img
        src="/doctora-avatar.png" // 👈 asegúrate que esta imagen esté en /public
        alt="Asistente Doctora"
        style={styles.avatar}
        animate={{
          y: [0, -12, 0], // efecto flotante
        }}
        transition={{
          duration: 3.5,
          repeat: Infinity,
          ease: "easeInOut",
        }}
      />

      {/* Burbuja de mensaje */}
      <motion.div
        style={styles.mensajeBox}
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.8 }}
      >
        <strong style={{ color: "#0D47A1" }}>Asistente Doctora</strong>
        <p style={styles.mensaje}>{mensaje}</p>
      </motion.div>
    </div>
  );
}

const styles = {
  wrapper: {
    position: "fixed",
    bottom: "30px",  // se puede mover aqui
    left: "30px",
    display: "flex",
    alignItems: "flex-end",
    gap: "16px",
    zIndex: 2000,
  },
  avatar: {
    width: "180px",   // grande
    height: "auto",
    cursor: "pointer",
  },
  mensajeBox: {
    background: "#fff",
    padding: "14px 18px",
    borderRadius: "14px",
    boxShadow: "0 6px 14px rgba(0,0,0,0.25)",
    maxWidth: "260px",
  },
  mensaje: {
    fontSize: "15px",
    color: "#2c3e50",
    marginTop: 6,
    fontStyle: "italic",
    lineHeight: "1.4",
  },
};

