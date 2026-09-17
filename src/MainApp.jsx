// src/MainApp.jsx

import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  useParams,
  useNavigate
} from "react-router-dom";

import "./index.css";
import MainLayout from "./layouts/MainLayout";

// ==================================================
// COMPONENTES
// ==================================================
import FaceScanner from "./components/FaceScanner";
import ReportViewer from "./components/ReportViewer";
import Pacientes from "./components/Pacientes";
import RegistrarPaciente from "./components/RegistrarPaciente";
import PacienteDetalle from "./components/PacienteDetalle";
import { usePatient } from "./components/PatientContext.jsx";

// ==================================================
// VISTAS
// ==================================================
import LoginView from "./views/LoginView";
import RegisterPsychologist from "./views/RegisterPsychologist";
import RegisterAdmin from "./views/RegisterAdmin";
import PsychologistView from "./views/PsychologistView";
import ChangePasswordView from "./views/ChangePasswordView";
import PruebasView from "./views/PruebasView";
import Dashboard from "./views/Dashboard";
import CalendarView from "./views/CalendarView";
import ResultadosPaciente from "./views/ResultadosPaciente";
import ResponderPrueba from "./views/ResponderPrueba";
import HistorialInicialView from "./views/HistorialInicialView";
import SeguimientoView from "./views/SeguimientoView";
import ResultadosPruebasView from "./views/ResultadosPruebasView";
import SesionesView from "./views/SesionesView";

// ==================================================
// RH
// ==================================================
import RegisterUsuarioRH from "./views/RegisterUsuarioRH";
import UsuariosRH from "./views/UsuariosRH";
import DetalleProspecto from "./views/DetalleProspecto";
import RegistrarProspecto from "./views/RegistrarProspecto";
import ProspectosRH from "./views/ProspectosRH";

// ==================================================
// EDUCATIVO
// ==================================================
import RegisterUsuarioEducativo from "./views/RegisterUsuarioEducativo";
import UsuariosEducativo from "./views/UsuariosEducativo";

// ==================================================
// INDEPENDIENTES
// ==================================================
import RegisterUsuarioIndependiente from "./views/RegisterUsuarioIndependiente";
import UsuariosIndependiente from "./views/UsuariosIndependiente";

// ==================================================
// VIDEOLLAMADAS
// ==================================================
import SalaVideollamada from "./views/SalaVideollamada.jsx";
import VideollamadaPaciente from "./views/VideollamadaPaciente.jsx";

// ==================================================
// SERVICIOS
// ==================================================
import { getToken, getCurrentUser } from "./services/AuthService";

// ==================================================
// RUTA PRUEBAS DEL PACIENTE
// ==================================================
function PruebasPacienteRoute() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();
  const user = getCurrentUser();

  return (
    <MainLayout onNavigate={() => navigate("/")}>
      <PruebasView
        idPaciente={Number(idPaciente)}
        token={user?.token || getToken()}
        onBack={() => navigate(`/paciente/${idPaciente}`)}
      />
    </MainLayout>
  );
}

// ==================================================
// PRUEBAS DE UNA SESIÓN ESPECÍFICA
// ==================================================
function PruebasSesionRoute() {
  const { idPaciente, idSesion } = useParams();
  const navigate = useNavigate();
  const user = getCurrentUser();

  return (
    <MainLayout onNavigate={() => navigate("/")}>
      <PruebasView
        idPaciente={Number(idPaciente)}
        idSesion={Number(idSesion)}
        token={user?.token || getToken()}
        onBack={() => navigate(`/paciente/${idPaciente}/sesiones`)}
      />
    </MainLayout>
  );
}

// ==================================================
// REPORTES IA GENERALES DEL PACIENTE
// ==================================================
function ReportesPacienteRoute() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();

  return (
    <MainLayout onNavigate={() => navigate("/")}>
      <div style={reportesPage}>
        <ReportViewer
          pacienteId={Number(idPaciente)}
          reporte={null}
          iaInsights={null}
        />

        <button
          style={backFromToolButton}
          onClick={() => navigate(`/paciente/${idPaciente}`)}
        >
          ⬅️ Volver al expediente
        </button>
      </div>
    </MainLayout>
  );
}

// ==================================================
// PREANÁLISIS IA DE UNA SESIÓN ESPECÍFICA
// NUEVO FLUJO:
// SESIÓN -> TERMINAR CONSULTA -> PREANÁLISIS IA
// ==================================================
function PreanalisisSesionRoute() {
  const { idPaciente, idSesion } = useParams();
  const navigate = useNavigate();

  return (
    <MainLayout onNavigate={() => navigate("/")}>
      <div style={reportesPage}>
        <ReportViewer
          pacienteId={Number(idPaciente)}
          idSesion={Number(idSesion)}
          reporte={null}
          iaInsights={null}
        />

        <button
          style={backFromToolButton}
          onClick={() =>
            navigate(`/paciente/${idPaciente}/sesiones`)
          }
        >
          ⬅️ Volver a sesiones
        </button>
      </div>
    </MainLayout>
  );
}

// ==================================================
// CITAS / AGENDA GENERAL POR RUTA
// ==================================================
function CitasRoute() {
  const navigate = useNavigate();

  return (
    <MainLayout onNavigate={() => navigate("/")}>
      <CalendarView onBack={() => navigate("/")} />
    </MainLayout>
  );
}

// ==================================================
// VIDEOLLAMADA DEL PACIENTE
// ==================================================
function VideollamadaPacienteRoute() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();

  return (
    <MainLayout onNavigate={() => navigate("/")}>
      <div style={videollamadaPage}>
        <VideollamadaPaciente
          pacienteId={Number(idPaciente)}
        />

        <button
          style={backFromToolButton}
          onClick={() => navigate(`/paciente/${idPaciente}`)}
        >
          ⬅️ Volver al expediente
        </button>
      </div>
    </MainLayout>
  );
}

// ==================================================
// REGISTRAR PROSPECTO RH PROVISIONAL
// ==================================================
function RegistrarProspectoRH({ onBack }) {
  return (
    <div style={placeholderPage}>
      <h2>👤 Registrar prospecto</h2>

      <p>
        Registro de prospectos del área de Recursos Humanos.
      </p>

      <button
        style={backFromToolButton}
        onClick={onBack}
      >
        ← Volver
      </button>
    </div>
  );
}

// ==================================================
// EMPLEADOS RH PROVISIONAL
// ==================================================
function EmpleadosRH({ onBack }) {
  return (
    <div style={placeholderPage}>
      <h2>👔 Empleados</h2>

      <p>
        Consulta y gestiona los empleados de Recursos Humanos.
      </p>

      <button
        style={backFromToolButton}
        onClick={onBack}
      >
        ← Volver
      </button>
    </div>
  );
}

// ==================================================
// CITAS RH PROVISIONAL
// ==================================================
function CitasRH({ onBack }) {
  return (
    <div style={placeholderPage}>
      <h2>📅 Calendario RH</h2>

      <p>
        Gestiona entrevistas, citas y actividades de Recursos Humanos.
      </p>

      <button
        style={backFromToolButton}
        onClick={onBack}
      >
        ← Volver
      </button>
    </div>
  );
}

// ==================================================
// APP
// ==================================================
const MainApp = () => {
  const [view, setView] = useState("landing");
  const [user, setUser] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);

  const { paciente } = usePatient();

  const [reporteFinal, setReporteFinal] = useState(null);

  // ==================================================
  // USUARIO ACTUAL
  // ==================================================
  useEffect(() => {
    const u = getCurrentUser();

    if (u) {
      setUser(u);
      setIsAdmin(u.role === 1);
      setView("dashboard");
    } else {
      setUser(null);
      setIsAdmin(false);
      setView("landing");
    }
  }, []);

  const resetEvaluacion = () => setReporteFinal(null);

  // ==================================================
  // CONTENIDO LEGACY
  // ==================================================
  const LegacyContent = () => (
    <div className="app-container">
      <AnimatePresence mode="wait">

        {/* =================================================
            LANDING
        ================================================= */}
        {view === "landing" && (
          <motion.div
            key="landing"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={landingContainer}
          >
            <div style={glowOne} />
            <div style={glowTwo} />

            <motion.div
              style={{
                ...emotion,
                top: "15%",
                left: "18%"
              }}
              animate={{
                y: [0, -18, 0],
                rotate: [-5, 5, -5]
              }}
              transition={{
                duration: 4,
                repeat: Infinity,
                ease: "easeInOut"
              }}
            >
              😊
            </motion.div>

            <motion.div
              style={{
                ...emotion,
                top: "20%",
                right: "18%"
              }}
              animate={{
                y: [0, 16, 0],
                rotate: [5, -5, 5]
              }}
              transition={{
                duration: 4.5,
                repeat: Infinity,
                ease: "easeInOut"
              }}
            >
              😌
            </motion.div>

            <motion.div
              style={{
                ...emotion,
                bottom: "20%",
                left: "15%"
              }}
              animate={{
                y: [0, -14, 0],
                rotate: [4, -4, 4]
              }}
              transition={{
                duration: 5,
                repeat: Infinity,
                ease: "easeInOut"
              }}
            >
              😢
            </motion.div>

            <motion.div
              style={{
                ...emotion,
                bottom: "18%",
                right: "16%"
              }}
              animate={{
                y: [0, 18, 0],
                rotate: [-4, 4, -4]
              }}
              transition={{
                duration: 4.8,
                repeat: Infinity,
                ease: "easeInOut"
              }}
            >
              ❤️
            </motion.div>

            <motion.div
              style={{
                ...emotionSmall,
                top: "35%",
                left: "8%"
              }}
              animate={{
                y: [0, -12, 0],
                opacity: [.5, 1, .5]
              }}
              transition={{
                duration: 3.5,
                repeat: Infinity
              }}
            >
              😴
            </motion.div>

            <motion.div
              style={{
                ...emotionSmall,
                top: "40%",
                right: "8%"
              }}
              animate={{
                y: [0, 12, 0],
                opacity: [.5, 1, .5]
              }}
              transition={{
                duration: 4,
                repeat: Infinity
              }}
            >
              🤯
            </motion.div>

            <motion.div
              initial={{
                opacity: 0,
                scale: .92,
                y: 20
              }}
              animate={{
                opacity: 1,
                scale: 1,
                y: 0
              }}
              transition={{
                duration: .8,
                ease: "easeOut"
              }}
              style={landingCard}
            >
              <motion.div
                animate={{
                  y: [0, -10, 0],
                  scale: [1, 1.06, 1]
                }}
                transition={{
                  duration: 4,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
                style={landingLogoContainer}
              >
                <img
                  src="/logo.png"
                  alt="MirrorSoul"
                  style={landingLogo}
                />
              </motion.div>

              <h1 style={landingTitle}>
                Mirror
                <span style={landingTitleAccent}>
                  Soul
                </span>
              </h1>

              <motion.h2
                initial={{
                  opacity: 0,
                  y: 10
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
                transition={{
                  delay: .4
                }}
                style={landingSlogan}
              >
                Conoce lo que sientes.
                <br />
                <span>
                  Comprende lo que eres.
                </span>
              </motion.h2>

              <p style={landingDescription}>
                Una herramienta inteligente para acompañar al profesional
                en la exploración emocional, evaluación y seguimiento
                de sus pacientes.
              </p>

              <motion.button
                onClick={() => setView("login")}
                style={landingButton}
                whileHover={{
                  scale: 1.05,
                  boxShadow:
                    "0 12px 30px rgba(30,136,229,.40)"
                }}
                whileTap={{
                  scale: .97
                }}
              >
                <span>
                  Entrar a MirrorSoul
                </span>

                <span style={{ fontSize: 20 }}>
                  →
                </span>
              </motion.button>

              <div style={landingFooter}>
                <span>✦</span>
                Tecnología que acompaña la salud emocional
                <span>✦</span>
              </div>
            </motion.div>
          </motion.div>
        )}

        {/* =================================================
            LOGIN
        ================================================= */}
        {view === "login" && (
          <LoginView
            key="login"
            onLoginSuccess={(u) => {
              setUser(u);
              setIsAdmin(u?.role === 1);
              setView("dashboard");
            }}
            onBack={() => setView("landing")}
          />
        )}

        {/* =================================================
            DASHBOARD
        ================================================= */}
        {view === "dashboard" && (
          <Dashboard
            key="dashboard"
            onNavigate={setView}
          />
        )}

        {/* =================================================
            PRUEBAS
        ================================================= */}
        {view === "pruebas" && (
          <PruebasView
            key="pruebas"
            idPaciente={paciente?.id_paciente}
            token={user?.token || getToken()}
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            FACE SCANNER
        ================================================= */}
        {view === "facescanner" && (
          <FaceScanner
            key="facescanner"
            pacienteId={paciente?.id_paciente}
            pruebaId={1}
            onFinish={() => setView("reporte")}
          />
        )}

        {/* =================================================
            PSICÓLOGOS
        ================================================= */}
        {view === "psychologistView" && isAdmin && (
          <PsychologistView
            key="psychologistView"
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            REPORTE
        ================================================= */}
        {view === "reporte" && (
          <div
            key="reporte"
            style={{
              textAlign: "center"
            }}
          >
            <ReportViewer
              reporte={reporteFinal}
              pacienteId={paciente?.id_paciente}
              iaInsights={
                "Aquí se mostraría el análisis de la IA"
              }
            />

            <div
              style={{
                marginTop: 20,
                display: "flex",
                gap: 15,
                justifyContent: "center"
              }}
            >
              <button
                onClick={() => {
                  resetEvaluacion();
                  setView("facescanner");
                }}
                style={{
                  ...buttonPrimary,
                  backgroundColor: "#4FC3F7"
                }}
              >
                🔁 Reiniciar evaluación
              </button>

              <button
                onClick={() => {
                  resetEvaluacion();
                  setView("dashboard");
                }}
                style={{
                  ...buttonPrimary,
                  backgroundColor: "#81C784"
                }}
              >
                ⬅️ Volver al Dashboard
              </button>
            </div>
          </div>
        )}

        {/* =================================================
            PACIENTES
        ================================================= */}
        {view === "pacientes" && (
          <Pacientes
            key="pacientes"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "registrarPaciente" && (
          <RegistrarPaciente
            key="registrarPaciente"
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            CAMBIAR PASSWORD
        ================================================= */}
        {view === "cambiarPassword" && (
          <ChangePasswordView
            key="cambiarPassword"
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            CITAS
        ================================================= */}
        {view === "citas" && (
          <CalendarView
            key="citas"
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            RESULTADOS
        ================================================= */}
        {view === "resultadosPaciente" && (
          <ResultadosPaciente
            key="resultadosPaciente"
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            ADMIN
        ================================================= */}
        {view === "registerPsychologist" && isAdmin && (
          <RegisterPsychologist
            key="registerPsychologist"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "registerAdmin" &&
          user?.role === 1 &&
          user?.tipo_admin === "master" && (
            <RegisterAdmin
              key="registerAdmin"
              onBack={() => setView("dashboard")}
            />
        )}

        {/* =================================================
            RH
        ================================================= */}
        {view === "registerUsuarioRH" && (
          <RegisterUsuarioRH
            key="registerUsuarioRH"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "usuariosRH" && (
          <UsuariosRH
            key="usuariosRH"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "registrarProspecto" && (
          <RegistrarProspecto
            key="registrarProspecto"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "prospectosRH" && (
          <ProspectosRH
            key="prospectosRH"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "empleadosRH" && (
          <EmpleadosRH
            key="empleadosRH"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "citasRH" && (
          <CitasRH
            key="citasRH"
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            EDUCATIVO
        ================================================= */}
        {view === "registerUsuarioEducativo" && (
          <RegisterUsuarioEducativo
            key="registerUsuarioEducativo"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "usuariosEducativo" && (
          <UsuariosEducativo
            key="usuariosEducativo"
            onBack={() => setView("dashboard")}
          />
        )}

        {/* =================================================
            INDEPENDIENTES
        ================================================= */}
        {view === "registerUsuarioIndependiente" && (
          <RegisterUsuarioIndependiente
            key="registerUsuarioIndependiente"
            onBack={() => setView("dashboard")}
          />
        )}

        {view === "usuariosIndependiente" && (
          <UsuariosIndependiente
            key="usuariosIndependiente"
            onBack={() => setView("dashboard")}
          />
        )}

      </AnimatePresence>
    </div>
  );

  // ==================================================
  // LEGACY SHELL
  // ==================================================
  function LegacyShell() {
    const publicView =
      view === "landing" ||
      view === "login";

    return publicView
      ? <LegacyContent />
      : (
        <MainLayout onNavigate={setView}>
          <LegacyContent />
        </MainLayout>
      );
  }

  // ==================================================
  // ROUTER
  // ==================================================
  return (
    <Router>
      <Routes>

        {/* =================================================
            PRUEBAS
        ================================================= */}
        <Route
          path="/prueba/:idHabilitacion"
          element={<ResponderPrueba />}
        />

        <Route
          path="/responder-prueba/:id_habilitacion"
          element={<ResponderPrueba />}
        />

        {/* =================================================
            VIDEOLLAMADAS
        ================================================= */}
        <Route
          path="/videollamada-paciente/:sala"
          element={<VideollamadaPaciente />}
        />

        <Route
          path="/SalaVideollamada/nueva/:idPaciente"
          element={<SalaVideollamada />}
        />

        <Route
          path="/SalaVideollamada/:sala"
          element={<SalaVideollamada />}
        />

        {/* =================================================
            PACIENTES
        ================================================= */}
        <Route
          path="/paciente/:idPaciente"
          element={
            <PacienteDetalle
              onBack={() =>
                window.history.back()
              }
            />
          }
        />

        <Route
          path="/paciente/:idPaciente/pruebas"
          element={<PruebasPacienteRoute />}
        />

        <Route
          path="/paciente/:idPaciente/sesion/:idSesion/pruebas"
          element={<PruebasSesionRoute />}
        />

        <Route
          path="/paciente/:idPaciente/reportes-ia"
          element={<ReportesPacienteRoute />}
        />

        {/* =================================================
            NUEVO: PREANÁLISIS IA DE SESIÓN
        ================================================= */}
        <Route
          path="/paciente/:idPaciente/sesion/:idSesion/preanalisis"
          element={<PreanalisisSesionRoute />}
        />

        {/* =================================================
            CIERRE CLÍNICO DE UNA SESIÓN ESPECÍFICA
        ================================================= */}
        <Route
          path="/paciente/:idPaciente/sesion/:idSesion/cierre"
          element={<SeguimientoView />}
        />

        <Route
          path="/paciente/:idPaciente/videollamada"
          element={<VideollamadaPacienteRoute />}
        />

        <Route
          path="/paciente/:idPaciente/historial"
          element={<HistorialInicialView />}
        />

        <Route
          path="/paciente/:idPaciente/seguimiento"
          element={<SeguimientoView />}
        />

        <Route
          path="/paciente/:idPaciente/resultados"
          element={<ResultadosPruebasView />}
        />

        <Route
          path="/paciente/:idPaciente/sesiones"
          element={<SesionesView />}
        />

        {/* =================================================
            CITAS / AGENDA GENERAL
        ================================================= */}
        <Route
          path="/citas"
          element={<CitasRoute />}
        />

        {/* =================================================
            RH
        ================================================= */}
        <Route
          path="/rh/usuarios"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <UsuariosRH />
            </MainLayout>
          }
        />

        <Route
          path="/rh/registrar-usuario"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <RegisterUsuarioRH />
            </MainLayout>
          }
        />

        <Route
          path="/prospectos"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <ProspectosRH />
            </MainLayout>
          }
        />

        <Route
          path="/registrar-prospecto"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <RegistrarProspecto />
            </MainLayout>
          }
        />

        <Route
          path="/prospecto/:idProspecto"
          element={<DetalleProspecto />}
        />

        {/* =================================================
            EDUCATIVO
        ================================================= */}
        <Route
          path="/educativo/usuarios"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <UsuariosEducativo />
            </MainLayout>
          }
        />

        <Route
          path="/educativo/registrar-usuario"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <RegisterUsuarioEducativo />
            </MainLayout>
          }
        />

        {/* =================================================
            INDEPENDIENTE
        ================================================= */}
        <Route
          path="/independiente/usuarios"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <UsuariosIndependiente />
            </MainLayout>
          }
        />

        <Route
          path="/independiente/registrar-usuario"
          element={
            <MainLayout
              onNavigate={() =>
                window.history.back()
              }
            >
              <RegisterUsuarioIndependiente />
            </MainLayout>
          }
        />

        {/* =================================================
            RESTO
        ================================================= */}
        <Route
          path="*"
          element={<LegacyShell />}
        />

      </Routes>
    </Router>
  );
};

// ==================================================
// ESTILOS
// ==================================================
const reportesPage = {
  maxWidth: "1100px",
  margin: "0 auto",
  padding: "30px 20px"
};

const videollamadaPage = {
  maxWidth: "1100px",
  margin: "0 auto",
  padding: "30px 20px"
};

const placeholderPage = {
  maxWidth: "850px",
  margin: "40px auto",
  padding: "40px",
  background: "#fff",
  borderRadius: "18px",
  boxShadow:
    "0 8px 24px rgba(40,80,140,.08)",
  textAlign: "center",
  fontFamily:
    "'Segoe UI',Arial,sans-serif",
  color: "#1A2B4B"
};

const backFromToolButton = {
  marginTop: 20,
  padding: "12px 22px",
  border: "none",
  borderRadius: 10,
  background:
    "linear-gradient(135deg,#64B5F6,#1976D2)",
  color: "#fff",
  fontWeight: 700,
  cursor: "pointer",
  fontSize: 15
};

const buttonPrimary = {
  padding: "14px 32px",
  borderRadius: 30,
  background:
    "linear-gradient(90deg,#64B5F6,#1E88E5)",
  color: "#fff",
  border: "none",
  cursor: "pointer",
  fontWeight: 600,
  fontSize: 18,
  boxShadow:
    "0 6px 14px rgba(30,136,229,.4)",
  transition:
    "transform .2s ease,box-shadow .2s ease"
};

const landingContainer = {
  position: "relative",
  minHeight: "100vh",
  width: "100%",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  overflow: "hidden",
  background:
    "radial-gradient(circle at center,#F8FCFF 0%,#EAF4FF 45%,#DCEEFF 100%)",
  fontFamily:
    "'Segoe UI',sans-serif"
};

const landingCard = {
  position: "relative",
  zIndex: 5,
  width: "min(680px,90%)",
  textAlign: "center",
  padding: "40px 35px",
  borderRadius: 30,
  background:
    "rgba(255,255,255,.62)",
  border:
    "1px solid rgba(255,255,255,.8)",
  boxShadow:
    "0 25px 70px rgba(40,100,170,.14)",
  backdropFilter: "blur(12px)"
};

const landingLogoContainer = {
  width: 300,
  height: 150,
  margin: "0 auto 18px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  borderRadius: 22,
  background:
    "linear-gradient(145deg,rgba(255,255,255,.98),rgba(225,240,255,.90))",
  boxShadow:
    "0 15px 40px rgba(55,125,190,.18)",
  backdropFilter: "blur(8px)",
  overflow: "hidden"
};

const landingLogo = {
  width: 280,
  height: 135,
  objectFit: "contain",
  display: "block",
  filter:
    "drop-shadow(0 8px 15px rgba(40,100,160,.20))"
};

const landingTitle = {
  margin: "8px 0 0",
  fontSize: 48,
  fontWeight: 800,
  letterSpacing: "-1.5px",
  color: "#173B68"
};

const landingTitleAccent = {
  color: "#4A90E2"
};

const landingSlogan = {
  margin: "18px 0 0",
  fontSize: 28,
  lineHeight: 1.3,
  fontWeight: 700,
  color: "#263B5A"
};

const landingDescription = {
  maxWidth: 560,
  margin: "18px auto 0",
  fontSize: 16,
  lineHeight: 1.7,
  color: "#526579"
};

const landingButton = {
  marginTop: 30,
  padding: "14px 26px",
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 12,
  border: "none",
  borderRadius: 30,
  background:
    "linear-gradient(135deg,#64B5F6,#1976D2)",
  color: "#fff",
  fontSize: 16,
  fontWeight: 700,
  cursor: "pointer",
  boxShadow:
    "0 8px 22px rgba(30,136,229,.30)",
  transition:
    "all .25s ease"
};

const landingFooter = {
  marginTop: 28,
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  gap: 10,
  fontSize: 12,
  color: "#78909C",
  letterSpacing: ".3px"
};

const emotion = {
  position: "absolute",
  zIndex: 2,
  width: 65,
  height: 65,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  borderRadius: "50%",
  background:
    "rgba(255,255,255,.65)",
  border:
    "1px solid rgba(255,255,255,.9)",
  boxShadow:
    "0 12px 30px rgba(60,120,180,.12)",
  backdropFilter: "blur(8px)",
  fontSize: 32
};

const emotionSmall = {
  position: "absolute",
  zIndex: 1,
  width: 48,
  height: 48,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  borderRadius: "50%",
  background:
    "rgba(255,255,255,.45)",
  boxShadow:
    "0 8px 20px rgba(60,120,180,.10)",
  fontSize: 24
};

const glowOne = {
  position: "absolute",
  width: 400,
  height: 400,
  borderRadius: "50%",
  background:
    "rgba(100,181,246,.16)",
  filter: "blur(70px)",
  top: -180,
  left: -120
};

const glowTwo = {
  position: "absolute",
  width: 350,
  height: 350,
  borderRadius: "50%",
  background:
    "rgba(129,199,132,.12)",
  filter: "blur(70px)",
  bottom: -150,
  right: -100
};

export default MainApp;