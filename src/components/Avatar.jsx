// src/components/Avatar.jsx

import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  AnimatePresence,
  motion
} from "framer-motion";

// =====================================================
// RECORDATORIOS CLÍNICOS
//
// Estos NO son pendientes inventados.
// Son avisos permanentes sobre el uso correcto
// de MirrorSoul.
// =====================================================

const recordatoriosClinicos = [
  "👤 Recuerda registrar primero al paciente para crear su expediente clínico.",

  "📋 El historial clínico inicial reúne la información base y los antecedentes del paciente.",

  "🩺 La sesión es el centro del trabajo clínico en MirrorSoul.",

  "📝 Durante una sesión puedes registrar seguimiento, notas y observaciones importantes.",

  "🧪 Las pruebas psicológicas son herramientas de apoyo y deben interpretarse junto con el contexto clínico.",

  "🎙️ El audio de una sesión presencial es opcional y puede utilizarse como apoyo cuando sea necesario.",

  "📞 La videollamada puede utilizarse cuando la consulta se realiza a distancia.",

  "🧠 MirrorSoul genera un Preanálisis IA como apoyo para el profesional.",

  "⚕️ El diagnóstico clínico final corresponde al psicólogo; la IA no sustituye su criterio profesional.",

  "🔎 Revisa siempre el Preanálisis IA antes de finalizar una sesión.",

  "⚠️ El resultado de una prueba psicológica por sí solo no establece un diagnóstico.",

  "📑 Para una valoración clínica deben considerarse entrevista, historial, observaciones, pruebas y evolución del paciente.",

  "✅ Después de revisar el Preanálisis IA puedes finalizar la sesión clínica.",

  "📅 Después de finalizar una sesión puedes decidir si es necesario programar una próxima cita.",

  "🧠 El Preanálisis IA utiliza únicamente la información disponible en el expediente y la sesión.",

  "📁 Desde el expediente puedes consultar historial, seguimiento, resultados, sesiones y herramientas clínicas."
];

export default function Avatar({
  mensajesContextuales = [],
  mensajeContextual = ""
}) {
  // =====================================================
  // CONSTRUIR LISTA COMPLETA
  //
  // ORDEN:
  // 1. Avisos reales del sistema
  // 2. Mensaje contextual
  // 3. Recordatorios clínicos
  // =====================================================

  const mensajes = useMemo(() => {
    const lista = [];

    // =================================================
    // MENSAJES REALES DEL DASHBOARD
    //
    // Ejemplos:
    // "Tienes 2 pacientes"
    // "Tienes una sesión activa"
    // "Tu próxima cita es..."
    // =================================================

    if (
      Array.isArray(
        mensajesContextuales
      )
    ) {
      mensajesContextuales
        .filter(Boolean)
        .forEach((item) => {
          const texto =
            String(item).trim();

          if (
            texto &&
            !lista.includes(texto)
          ) {
            lista.push(texto);
          }
        });
    }

    // =================================================
    // MENSAJE CONTEXTUAL INDIVIDUAL
    // =================================================

    if (mensajeContextual) {
      const texto =
        String(
          mensajeContextual
        ).trim();

      if (
        texto &&
        !lista.includes(texto)
      ) {
        lista.push(texto);
      }
    }

    // =================================================
    // RECORDATORIOS CLÍNICOS
    // =================================================

    recordatoriosClinicos.forEach(
      (item) => {
        if (
          !lista.includes(item)
        ) {
          lista.push(item);
        }
      }
    );

    return lista;
  }, [
    mensajeContextual,
    mensajesContextuales
  ]);

  // =====================================================
  // MENSAJE ACTUAL
  // =====================================================

  const [
    indice,
    setIndice
  ] = useState(0);

  // =====================================================
  // EVITAR QUE EL ÍNDICE QUEDE FUERA DE LA LISTA
  // =====================================================

  useEffect(() => {
    setIndice((actual) => {
      if (
        actual >= mensajes.length
      ) {
        return 0;
      }

      return actual;
    });
  }, [mensajes.length]);

  // =====================================================
  // CAMBIAR MENSAJE AUTOMÁTICAMENTE
  // CADA 6 SEGUNDOS
  // =====================================================

  useEffect(() => {
    if (
      mensajes.length <= 1
    ) {
      return;
    }

    const interval =
      setInterval(() => {
        setIndice(
          (actual) =>
            (actual + 1) %
            mensajes.length
        );
      }, 6000);

    return () => {
      clearInterval(interval);
    };
  }, [mensajes.length]);

  // =====================================================
  // MENSAJE MOSTRADO
  // =====================================================

  const mensaje =
    mensajes[indice] ||
    "🧠 MirrorSoul está listo para ayudarte.";

  // =====================================================
  // SIGUIENTE MENSAJE
  // =====================================================

  const siguienteMensaje =
    () => {
      if (
        mensajes.length <= 1
      ) {
        return;
      }

      setIndice(
        (actual) =>
          (actual + 1) %
          mensajes.length
      );
    };

  // =====================================================
  // MENSAJE ANTERIOR
  // =====================================================

  const mensajeAnterior =
    () => {
      if (
        mensajes.length <= 1
      ) {
        return;
      }

      setIndice(
        (actual) =>
          actual === 0
            ? mensajes.length - 1
            : actual - 1
      );
    };

  // =====================================================
  // RENDER
  // =====================================================

  return (
    <div style={styles.wrapper}>

      {/* ===============================================
          AVATAR
      =============================================== */}

      <motion.img
        src="/doctora-avatar.png"
        alt="Asistente MirrorSoul"
        style={styles.avatar}
        animate={{
          y: [
            0,
            -8,
            0
          ]
        }}
        transition={{
          duration: 3.5,
          repeat: Infinity,
          ease: "easeInOut"
        }}
        onClick={
          siguienteMensaje
        }
        title="Haz clic para ver el siguiente aviso"
      />

      {/* ===============================================
          BURBUJA DE MENSAJE
      =============================================== */}

      <motion.div
        style={styles.mensajeBox}
        initial={{
          opacity: 0,
          x: 15
        }}
        animate={{
          opacity: 1,
          x: 0
        }}
        transition={{
          duration: 0.8
        }}
      >
        <div style={styles.titulo}>
          🧠 Asistente MirrorSoul
        </div>

        {/* =============================================
            MENSAJE ANIMADO
        ============================================= */}

        <AnimatePresence mode="wait">
          <motion.div
            key={`${indice}-${mensaje}`}
            style={styles.mensaje}
            initial={{
              opacity: 0,
              y: 5
            }}
            animate={{
              opacity: 1,
              y: 0
            }}
            exit={{
              opacity: 0,
              y: -5
            }}
            transition={{
              duration: 0.25
            }}
          >
            {mensaje}
          </motion.div>
        </AnimatePresence>

        {/* =============================================
            CONTROLES
        ============================================= */}

        {mensajes.length > 1 && (
          <div style={styles.controles}>
            <button
              type="button"
              style={styles.flecha}
              onClick={
                mensajeAnterior
              }
              title="Mensaje anterior"
            >
              ‹
            </button>

            <span
              style={
                styles.contador
              }
            >
              {indice + 1}
              {" / "}
              {mensajes.length}
            </span>

            <button
              type="button"
              style={styles.flecha}
              onClick={
                siguienteMensaje
              }
              title="Siguiente mensaje"
            >
              ›
            </button>
          </div>
        )}

        {/* =============================================
            INDICADORES
        ============================================= */}

        {mensajes.length > 1 && (
          <div
            style={
              styles.indicadores
            }
          >
            {mensajes.map(
              (_, i) => (
                <button
                  key={i}
                  type="button"
                  aria-label={
                    `Ver mensaje ${i + 1}`
                  }
                  onClick={() =>
                    setIndice(i)
                  }
                  style={{
                    ...styles.punto,

                    ...(i === indice
                      ? styles.puntoActivo
                      : {})
                  }}
                />
              )
            )}
          </div>
        )}

        {/* COLA DE LA BURBUJA */}

        <div
          style={
            styles.bubbleTail
          }
        />
      </motion.div>
    </div>
  );
}

// =====================================================
// ESTILOS
// =====================================================

const styles = {
  wrapper: {
    position: "relative",
    width: "385px",
    minHeight: "170px",

    display: "flex",
    alignItems: "center",
    justifyContent: "center",

    gap: "8px",

    zIndex: 50,

    boxSizing:
      "border-box"
  },

  avatar: {
    width: "145px",
    height: "auto",

    cursor: "pointer",

    display: "block",

    userSelect: "none",

    flexShrink: 0,

    zIndex: 51
  },

  mensajeBox: {
    width: "225px",

    minHeight: "120px",

    background:
      "linear-gradient(145deg,#FFFFFF,#F5FAFF)",

    padding:
      "12px 15px",

    borderRadius:
      "16px",

    boxShadow:
      "0 6px 18px rgba(40,80,140,.14)",

    border:
      "1px solid #E3ECF7",

    boxSizing:
      "border-box",

    position:
      "relative",

    textAlign:
      "left",

    zIndex: 52
  },

  titulo: {
    color: "#1759B7",

    fontSize: "12px",

    fontWeight: "800",

    marginBottom: "7px"
  },

  mensaje: {
    color: "#40566F",

    fontSize: "12px",

    lineHeight: "1.45",

    minHeight: "51px",

    display: "flex",

    alignItems: "flex-start"
  },

  controles: {
    display: "flex",

    alignItems: "center",

    justifyContent:
      "space-between",

    marginTop: "8px",

    paddingTop: "6px",

    borderTop:
      "1px solid #EDF2F7"
  },

  flecha: {
    width: "25px",

    height: "25px",

    border: "none",

    borderRadius: "50%",

    background:
      "#EEF4FF",

    color:
      "#2167D5",

    cursor: "pointer",

    display: "flex",

    alignItems: "center",

    justifyContent:
      "center",

    fontSize: "20px",

    lineHeight: "1",

    fontWeight: "700"
  },

  contador: {
    color: "#94A3B8",

    fontSize: "10px",

    fontWeight: "700"
  },

  indicadores: {
    display: "flex",

    flexWrap: "wrap",

    alignItems: "center",

    gap: "4px",

    marginTop: "7px",

    maxWidth: "190px"
  },

  punto: {
    width: "5px",

    height: "5px",

    minWidth: "5px",

    padding: 0,

    border: "none",

    borderRadius: "50%",

    background: "#CBD5E1",

    cursor: "pointer",

    transition:
      "all .2s ease"
  },

  puntoActivo: {
    width: "14px",

    borderRadius:
      "999px",

    background:
      "#4A7FF5"
  },

  bubbleTail: {
    position:
      "absolute",

    left: "-10px",

    top: "50%",

    transform:
      "translateY(-50%)",

    width: 0,

    height: 0,

    borderTop:
      "8px solid transparent",

    borderBottom:
      "8px solid transparent",

    borderRight:
      "11px solid #FFFFFF"
  }
};