// src/MainApp.jsx
import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import FaceScanner from "./components/FaceScanner";
import ReportViewer from "./components/ReportViewer";
import Pacientes from "./components/Pacientes";
import RegistrarPaciente from "./components/RegistrarPaciente";
import LoginView from "./views/LoginView";
import RegisterPsychologist from "./views/RegisterPsychologist";
import PsychologistView from "./views/PsychologistView";
import ChangePasswordView from "./views/ChangePasswordView";
import PruebasView from "./views/PruebasView";
import Dashboard from "./views/Dashboard";
import CalendarView from "./views/CalendarView";
import ResultadosPaciente from "./views/ResultadosPaciente";
import ResponderPrueba from "./views/ResponderPrueba"; // vista pública

// ✅ Nuevas vistas
import HistorialInicialView from "./views/HistorialInicialView";
import SeguimientoView from "./views/SeguimientoView";
import ResultadosPruebasView from "./views/ResultadosPruebasView";
import SesionesView from "./views/SesionesView";

// ✅ Import videollamadas
import SalaVideollamada from "./views/SalaVideollamada.jsx";
import VideollamadaPaciente from "./views/VideollamadaPaciente.jsx";

// ✅ NUEVO: importar Backup Manager
import BackupManager from "./views/BackupManager"; // 👈 AÑADIR

import { getToken, getCurrentUser } from "./services/AuthService";
import { usePatient } from "./components/PatientContext.jsx";

const MainApp = () => {
  const [view, setView] = useState("landing");
  const [user, setUser] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const { paciente } = usePatient();
  const [reporteFinal, setReporteFinal] = useState(null);

  useEffect(() => {
    const u = getCurrentUser();
    if (u) {
      setUser(u);
      setIsAdmin(u.role === 1); // 1 = admin
      setView("dashboard");
    } else {
      setView("landing");
    }
  }, []);

  const resetEvaluacion = () => {
    setReporteFinal(null);
  };

  // ✅ LegacyShell (landing + dashboard + otras vistas)
  const LegacyShell = () => (
    <div
      style={{
        background: "linear-gradient(180deg, #E3F2FD, #BBDEFB)",
        minHeight: "100vh",
        padding: 40,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        fontFamily: "'Poppins', 'Segoe UI', sans-serif",
        color: "#0D47A1",
        userSelect: "none",
      }}
    >
      <motion.div
        style={{
          background: "#fff",
          padding: "12px 18px",
          borderRadius: "16px",
          boxShadow: "0 6px 16px rgba(0,0,0,0.2)",
          marginBottom: 20,
        }}
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.8 }}
      >
        <motion.img
          src="/logo.png"
          alt="Logo"
          style={{ width: 180, height: "auto", borderRadius: "12px" }}
          animate={{ scale: [1, 1.08, 1], rotate: [0, 4, -4, 0] }}
          transition={{ duration: 6, repeat: Infinity }}
        />
      </motion.div>

      <AnimatePresence mode="wait">
        {view === "landing" && (
          <motion.div
            key="landing"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            style={{ textAlign: "center", marginTop: 40, maxWidth: "700px" }}
          >
            <h1 style={{ fontSize: "2.2rem", fontWeight: "800", color: "#1A237E" }}>
              🧠 Bienvenido a <span style={{ color: "#3f51b5" }}>MirrorSoul</span>
            </h1>
            <p style={{ fontSize: "18px", marginTop: 15, lineHeight: "1.6", color: "#37474F" }}>
              Identifica tus <strong>emociones</strong> y aprende a gestionarlas para vivir una vida plena.
              <br />
              MirrorSoul es una herramienta de apoyo diseñada para psicólogos donde podrás realizar
              <strong> pruebas de prediagnóstico emocional</strong>.
              <br />
              <span style={{ color: "#E91E63", fontWeight: "600" }}>
                📌 Aviso: el diagnóstico final corresponde siempre al profesional.
              </span>
            </p>
            <div style={{ marginTop: 30, display: "flex", justifyContent: "center" }}>
              <button onClick={() => setView("login")} style={buttonPrimary}>
                🚀 Iniciar sesión
              </button>
            </div>

            {/* Footer con emojis de emociones */}
            <div style={{ marginTop: "50px", fontSize: "26px" }}>
              😀 😢 😡 😍 😴 😱 🤯 🤗
            </div>
          </motion.div>
        )}

        {view === "dashboard" && <Dashboard key="dashboard" onNavigate={setView} />}
        {view === "backup" && <BackupManager key="backup" onBack={() => setView("dashboard")} />}
        {view === "pruebas" && (
          <PruebasView
            key="pruebas"
            idPaciente={paciente?.id_paciente}
            token={user?.token || getToken()}
            onBack={() => setView("dashboard")}
          />
        )}
        {view === "facescanner" && (
          <FaceScanner
            key="facescanner"
            pacienteId={paciente?.id_paciente}
            pruebaId={1}
            onFinish={() => setView("reporte")}
          />
        )}
        {view === "psychologistView" && isAdmin && (
          <PsychologistView key="psychologistView" onBack={() => setView("dashboard")} />
        )}
        {view === "reporte" && (
          <div key="reporte" style={{ textAlign: "center" }}>
            <ReportViewer
              reporte={reporteFinal}
              pacienteId={paciente?.id_paciente}
              iaInsights={"Aquí se mostraría el análisis de la IA"}
            />
            <div style={{ marginTop: 20, display: "flex", gap: "15px", justifyContent: "center" }}>
              <button
                onClick={() => {
                  resetEvaluacion();
                  setView("facescanner");
                }}
                style={{ ...buttonPrimary, backgroundColor: "#4FC3F7" }}
              >
                🔁 Reiniciar evaluación
              </button>
              <button
                onClick={() => {
                  resetEvaluacion();
                  setView("dashboard");
                }}
                style={{ ...buttonPrimary, backgroundColor: "#81C784" }}
              >
                ⬅️ Volver al Dashboard
              </button>
            </div>
          </div>
        )}
        {view === "pacientes" && <Pacientes key="pacientes" onBack={() => setView("dashboard")} />}
        {view === "login" && (
          <LoginView
            key="login"
            onLoginSuccess={(userData) => {
              setUser(userData);
              setIsAdmin(userData?.role === 1);
              setView("dashboard");
            }}
            onBack={() => setView("landing")}
          />
        )}
        {view === "registerPsychologist" && isAdmin && (
          <RegisterPsychologist key="registerPsychologist" onBack={() => setView("dashboard")} />
        )}
        {view === "registrarPaciente" && (
          <RegistrarPaciente key="registrarPaciente" onBack={() => setView("dashboard")} />
        )}
        {view === "cambiarPassword" && (
          <ChangePasswordView key="cambiarPassword" onBack={() => setView("dashboard")} />
        )}
        {view === "citas" && <CalendarView key="citas" onBack={() => setView("dashboard")} />}
        {view === "resultadosPaciente" && (
          <ResultadosPaciente key="resultadosPaciente" onBack={() => setView("dashboard")} />
        )}
      </AnimatePresence>
    </div>
  );

  // ✅ Router principal
  return (
    <Router>
      <Routes>
        {/* 📌 Ruta pública para que el paciente responda la prueba */}
        <Route path="/responder-prueba/:id_habilitacion" element={<ResponderPrueba />} />

        {/* 📌 Videollamadas */}
        <Route path="/SalaVideollamada/:sala" element={<SalaVideollamada />} />
        <Route path="/videollamada-paciente/:sala" element={<VideollamadaPaciente />} />

        {/* 📌 Vistas clínicas */}
        <Route path="/historial/:idPaciente" element={<HistorialInicialView />} />
        <Route path="/seguimiento/:idPaciente" element={<SeguimientoView />} />
        <Route path="/resultados/:idPaciente" element={<ResultadosPruebasView />} />
        <Route path="/sesiones/:idPaciente" element={<SesionesView />} />

        {/* 📌 Todas las demás rutas caen en LegacyShell */}
        <Route path="*" element={<LegacyShell />} />
      </Routes>
    </Router>
  );
};

// Estilos botón
const buttonPrimary = {
  padding: "14px 32px",
  borderRadius: "30px", // 👈 estilo píldora
  background: "linear-gradient(90deg, #64B5F6, #1E88E5)",
  color: "white",
  border: "none",
  cursor: "pointer",
  fontWeight: "600",
  fontSize: "18px",
  boxShadow: "0 6px 14px rgba(30, 136, 229, 0.4)",
  transition: "transform 0.2s ease, box-shadow 0.2s ease",
};

export default MainApp;
