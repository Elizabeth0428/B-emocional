// src/MainApp.jsx

import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

import {
  BrowserRouter as Router,
  Routes,
  Route,
  useParams,
  useNavigate,
} from "react-router-dom";

import "./index.css";

import MainLayout from "./layouts/MainLayout";

// =====================================================
// COMPONENTES
// =====================================================

import FaceScanner from "./components/FaceScanner";
import ReportViewer from "./components/ReportViewer";
import Pacientes from "./components/Pacientes";
import RegistrarPaciente from "./components/RegistrarPaciente";
import PacienteDetalle from "./components/PacienteDetalle";

// =====================================================
// VISTAS
// =====================================================

import LoginView from "./views/LoginView";
import RegisterPsychologist from "./views/RegisterPsychologist";
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

// =====================================================
// VIDEOLLAMADAS
// =====================================================

import SalaVideollamada from "./views/SalaVideollamada.jsx";
import VideollamadaPaciente from "./views/VideollamadaPaciente.jsx";

// =====================================================
// SERVICIOS
// =====================================================

import {
  getToken,
  getCurrentUser,
} from "./services/AuthService";

import { usePatient } from "./components/PatientContext.jsx";


// =====================================================
// RUTA DE PRUEBAS DEL PACIENTE
// =====================================================

function PruebasPacienteRoute() {

  const { idPaciente } = useParams();

  const navigate = useNavigate();

  const user = getCurrentUser();

  return (

    <MainLayout
      onNavigate={() => navigate("/")}
    >

      <PruebasView

        idPaciente={Number(idPaciente)}

        token={
          user?.token || getToken()
        }

        onBack={() =>
          navigate(`/paciente/${idPaciente}`)
        }

      />

    </MainLayout>

  );

}


// =====================================================
// RUTA DE REPORTES IA DEL PACIENTE
// =====================================================

function ReportesPacienteRoute() {

  const { idPaciente } = useParams();

  const navigate = useNavigate();

  return (

    <MainLayout
      onNavigate={() => navigate("/")}
    >

      <div style={reportesPage}>

        <ReportViewer

          pacienteId={
            Number(idPaciente)
          }

          reporte={null}

          iaInsights={null}

        />

        <button

          style={backFromToolButton}

          onClick={() =>
            navigate(`/paciente/${idPaciente}`)
          }

        >

          ⬅️ Volver al expediente

        </button>

      </div>

    </MainLayout>

  );

}


// =====================================================
// RUTA DE VIDEOLLAMADA DEL PACIENTE
// =====================================================

function VideollamadaPacienteRoute() {

  const { idPaciente } = useParams();

  const navigate = useNavigate();

  return (

    <MainLayout
      onNavigate={() => navigate("/")}
    >

      <div style={videollamadaPage}>

        <VideollamadaPaciente
          pacienteId={Number(idPaciente)}
        />

        <button
          style={backFromToolButton}
          onClick={() =>
            navigate(`/paciente/${idPaciente}`)
          }
        >

          ⬅️ Volver al expediente

        </button>

      </div>

    </MainLayout>

  );

}


// =====================================================
// MAIN APP
// =====================================================

const MainApp = () => {

  const [view, setView] =
    useState("landing");

  const [user, setUser] =
    useState(null);

  const [isAdmin, setIsAdmin] =
    useState(false);

  const { paciente } =
    usePatient();

  const [reporteFinal, setReporteFinal] =
    useState(null);


  // =====================================================
  // COMPROBAR SESIÓN
  // =====================================================

  useEffect(() => {

    const u =
      getCurrentUser();

    if (u) {

      setUser(u);

      setIsAdmin(
        u.role === 1
      );

      setView("dashboard");

    } else {

      setUser(null);

      setIsAdmin(false);

      setView("landing");

    }

  }, []);


  // =====================================================
  // REINICIAR EVALUACIÓN
  // =====================================================

  const resetEvaluacion = () => {

    setReporteFinal(null);

  };


  // =====================================================
  // CONTENIDO PRINCIPAL
  // =====================================================

  const LegacyContent = () => (

    <div className="app-container">

      <AnimatePresence mode="wait">


        {/* =================================================
            LANDING
        ================================================= */}

        {view === "landing" && (

          <motion.div

            key="landing"

            initial={{
              opacity: 0,
            }}

            animate={{
              opacity: 1,
            }}

            exit={{
              opacity: 0,
            }}

            style={landingContainer}

          >

            <div style={glowOne}></div>

            <div style={glowTwo}></div>


            <motion.div

              style={{
                ...emotion,
                top: "15%",
                left: "18%",
              }}

              animate={{
                y: [0, -18, 0],
                rotate: [-5, 5, -5],
              }}

              transition={{
                duration: 4,
                repeat: Infinity,
                ease: "easeInOut",
              }}

            >

              😊

            </motion.div>


            <motion.div

              style={{
                ...emotion,
                top: "20%",
                right: "18%",
              }}

              animate={{
                y: [0, 16, 0],
                rotate: [5, -5, 5],
              }}

              transition={{
                duration: 4.5,
                repeat: Infinity,
                ease: "easeInOut",
              }}

            >

              😌

            </motion.div>


            <motion.div

              style={{
                ...emotion,
                bottom: "20%",
                left: "15%",
              }}

              animate={{
                y: [0, -14, 0],
                rotate: [4, -4, 4],
              }}

              transition={{
                duration: 5,
                repeat: Infinity,
                ease: "easeInOut",
              }}

            >

              😢

            </motion.div>


            <motion.div

              style={{
                ...emotion,
                bottom: "18%",
                right: "16%",
              }}

              animate={{
                y: [0, 18, 0],
                rotate: [-4, 4, -4],
              }}

              transition={{
                duration: 4.8,
                repeat: Infinity,
                ease: "easeInOut",
              }}

            >

              ❤️

            </motion.div>


            <motion.div

              style={{
                ...emotionSmall,
                top: "35%",
                left: "8%",
              }}

              animate={{
                y: [0, -12, 0],
                opacity: [0.5, 1, 0.5],
              }}

              transition={{
                duration: 3.5,
                repeat: Infinity,
              }}

            >

              😴

            </motion.div>


            <motion.div

              style={{
                ...emotionSmall,
                top: "40%",
                right: "8%",
              }}

              animate={{
                y: [0, 12, 0],
                opacity: [0.5, 1, 0.5],
              }}

              transition={{
                duration: 4,
                repeat: Infinity,
              }}

            >

              🤯

            </motion.div>


            <motion.div

              initial={{
                opacity: 0,
                scale: 0.92,
                y: 20,
              }}

              animate={{
                opacity: 1,
                scale: 1,
                y: 0,
              }}

              transition={{
                duration: 0.8,
                ease: "easeOut",
              }}

              style={landingCard}

            >

              <motion.div

                animate={{
                  y: [0, -10, 0],
                  scale: [1, 1.06, 1],
                }}

                transition={{
                  duration: 4,
                  repeat: Infinity,
                  ease: "easeInOut",
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
                  y: 10,
                }}

                animate={{
                  opacity: 1,
                  y: 0,
                }}

                transition={{
                  delay: 0.4,
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
                en la exploración emocional, evaluación y seguimiento de sus pacientes.

              </p>


              <motion.button

                onClick={() =>
                  setView("login")
                }

                style={landingButton}

                whileHover={{
                  scale: 1.05,
                  boxShadow:
                    "0 12px 30px rgba(30,136,229,0.40)",
                }}

                whileTap={{
                  scale: 0.97,
                }}

              >

                <span>
                  Entrar a MirrorSoul
                </span>

                <span
                  style={{
                    fontSize: "20px",
                  }}
                >
                  →
                </span>

              </motion.button>


              <div style={landingFooter}>

                <span>
                  ✦
                </span>

                Tecnología que acompaña la salud emocional

                <span>
                  ✦
                </span>

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

            onLoginSuccess={(userData) => {

              setUser(userData);

              setIsAdmin(
                userData?.role === 1
              );

              setView("dashboard");

            }}

            onBack={() => {

              setView("landing");

            }}

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
            PRUEBAS LEGACY
        ================================================= */}

        {view === "pruebas" && (

          <PruebasView

            key="pruebas"

            idPaciente={
              paciente?.id_paciente
            }

            token={
              user?.token || getToken()
            }

            onBack={() =>
              setView("dashboard")
            }

          />

        )}


        {/* =================================================
            FACE SCANNER
        ================================================= */}

        {view === "facescanner" && (

          <FaceScanner

            key="facescanner"

            pacienteId={
              paciente?.id_paciente
            }

            pruebaId={1}

            onFinish={() =>
              setView("reporte")
            }

          />

        )}


        {/* =================================================
            PSYCHOLOGIST VIEW
        ================================================= */}

        {view === "psychologistView" &&
          isAdmin && (

            <PsychologistView

              key="psychologistView"

              onBack={() =>
                setView("dashboard")
              }

            />

          )}


        {/* =================================================
            REPORTE LEGACY
        ================================================= */}

        {view === "reporte" && (

          <div

            key="reporte"

            style={{
              textAlign: "center",
            }}

          >

            <ReportViewer

              reporte={reporteFinal}

              pacienteId={
                paciente?.id_paciente
              }

              iaInsights={
                "Aquí se mostraría el análisis de la IA"
              }

            />


            <div

              style={{
                marginTop: 20,
                display: "flex",
                gap: "15px",
                justifyContent: "center",
              }}

            >

              <button

                onClick={() => {

                  resetEvaluacion();

                  setView("facescanner");

                }}

                style={{
                  ...buttonPrimary,
                  backgroundColor: "#4FC3F7",
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
                  backgroundColor: "#81C784",
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

            onBack={() =>
              setView("dashboard")
            }

          />

        )}


        {/* =================================================
            REGISTRAR PACIENTE
        ================================================= */}

        {view === "registrarPaciente" && (

          <RegistrarPaciente

            key="registrarPaciente"

            onBack={() =>
              setView("dashboard")
            }

          />

        )}


        {/* =================================================
            CAMBIAR PASSWORD
        ================================================= */}

        {view === "cambiarPassword" && (

          <ChangePasswordView

            key="cambiarPassword"

            onBack={() =>
              setView("dashboard")
            }

          />

        )}


        {/* =================================================
            CITAS
        ================================================= */}

        {view === "citas" && (

          <CalendarView

            key="citas"

            onBack={() =>
              setView("dashboard")
            }

          />

        )}


        {/* =================================================
            RESULTADOS PACIENTE
        ================================================= */}

        {view === "resultadosPaciente" && (

          <ResultadosPaciente

            key="resultadosPaciente"

            onBack={() =>
              setView("dashboard")
            }

          />

        )}


        {/* =================================================
            REGISTRAR PSICÓLOGO
        ================================================= */}

        {view === "registerPsychologist" &&
          isAdmin && (

            <RegisterPsychologist

              key="registerPsychologist"

              onBack={() =>
                setView("dashboard")
              }

            />

          )}

      </AnimatePresence>

    </div>

  );


  // =====================================================
  // SHELL
  // =====================================================

  function LegacyShell() {

    const isPublicView =
      view === "landing" ||
      view === "login";


    if (isPublicView) {

      return (
        <LegacyContent />
      );

    }


    return (

      <MainLayout
        onNavigate={setView}
      >

        <LegacyContent />

      </MainLayout>

    );

  }


  // =====================================================
  // ROUTES
  // =====================================================

  return (

    <Router>

      <Routes>


        {/* =================================================
            PRUEBA PÚBLICA
        ================================================= */}

        <Route
          path="/prueba/:idHabilitacion"
          element={
            <ResponderPrueba />
          }
        />


        {/* =================================================
            COMPATIBILIDAD
        ================================================= */}

        <Route
          path="/responder-prueba/:id_habilitacion"
          element={
            <ResponderPrueba />
          }
        />


        {/* =================================================
            VIDEOLLAMADA PÚBLICA DEL PACIENTE
        ================================================= */}

        <Route
          path="/videollamada-paciente/:sala"
          element={
            <VideollamadaPaciente />
          }
        />


        {/* =================================================
            SALA PSICÓLOGO - INICIAR
        ================================================= */}

        <Route
          path="/SalaVideollamada/nueva/:idPaciente"
          element={
            <SalaVideollamada />
          }
        />


        {/* =================================================
            SALA PSICÓLOGO - SALA REAL
        ================================================= */}

        <Route
          path="/SalaVideollamada/:sala"
          element={
            <SalaVideollamada />
          }
        />


        {/* =================================================
            EXPEDIENTE DEL PACIENTE
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


        {/* =================================================
            PRUEBAS DEL PACIENTE
        ================================================= */}

        <Route
          path="/paciente/:idPaciente/pruebas"
          element={
            <PruebasPacienteRoute />
          }
        />


        {/* =================================================
            REPORTES IA
        ================================================= */}

        <Route
          path="/paciente/:idPaciente/reportes-ia"
          element={
            <ReportesPacienteRoute />
          }
        />


        {/* =================================================
            VIDEOLLAMADA DEL PACIENTE
        ================================================= */}

        <Route
          path="/paciente/:idPaciente/videollamada"
          element={
            <VideollamadaPacienteRoute />
          }
        />


        {/* =================================================
            HISTORIAL
        ================================================= */}

        <Route
          path="/paciente/:idPaciente/historial"
          element={
            <HistorialInicialView />
          }
        />


        {/* =================================================
            SEGUIMIENTO
        ================================================= */}

        <Route
          path="/paciente/:idPaciente/seguimiento"
          element={
            <SeguimientoView />
          }
        />


        {/* =================================================
            RESULTADOS
        ================================================= */}

        <Route
          path="/paciente/:idPaciente/resultados"
          element={
            <ResultadosPruebasView />
          }
        />


        {/* =================================================
            SESIONES
        ================================================= */}

        <Route
          path="/paciente/:idPaciente/sesiones"
          element={
            <SesionesView />
          }
        />


        {/* =================================================
            RESTO DE LA APLICACIÓN
        ================================================= */}

        <Route
          path="*"
          element={
            <LegacyShell />
          }
        />

      </Routes>

    </Router>

  );

};


// =========================================================
// ESTILOS DE HERRAMIENTAS
// =========================================================

const reportesPage = {

  maxWidth: "1100px",

  margin: "0 auto",

  padding: "30px 20px",

};


const videollamadaPage = {

  maxWidth: "1100px",

  margin: "0 auto",

  padding: "30px 20px",

};


const backFromToolButton = {

  marginTop: "20px",

  padding: "12px 22px",

  border: "none",

  borderRadius: "10px",

  background:
    "linear-gradient(135deg, #64B5F6, #1976D2)",

  color: "#fff",

  fontWeight: "700",

  cursor: "pointer",

  fontSize: "15px",

};


// =========================================================
// ESTILO BOTÓN PRINCIPAL
// =========================================================

const buttonPrimary = {

  padding: "14px 32px",

  borderRadius: "30px",

  background:
    "linear-gradient(90deg, #64B5F6, #1E88E5)",

  color: "white",

  border: "none",

  cursor: "pointer",

  fontWeight: "600",

  fontSize: "18px",

  boxShadow:
    "0 6px 14px rgba(30, 136, 229, 0.4)",

  transition:
    "transform 0.2s ease, box-shadow 0.2s ease",

};


// =========================================================
// ESTILOS LANDING
// =========================================================

const landingContainer = {

  position: "relative",

  minHeight: "calc(100vh - 0px)",

  width: "100%",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  overflow: "hidden",

  background:
    "radial-gradient(circle at center, #F8FCFF 0%, #EAF4FF 45%, #DCEEFF 100%)",

  fontFamily:
    "'Segoe UI', sans-serif",

};


const landingCard = {

  position: "relative",

  zIndex: 5,

  width: "min(680px, 90%)",

  textAlign: "center",

  padding: "40px 35px",

  borderRadius: "30px",

  background:
    "rgba(255,255,255,0.62)",

  border:
    "1px solid rgba(255,255,255,0.8)",

  boxShadow:
    "0 25px 70px rgba(40,100,170,0.14)",

  backdropFilter: "blur(12px)",

};


const landingLogoContainer = {

  width: "300px",

  height: "150px",

  margin: "0 auto 18px",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  borderRadius: "22px",

  background:
    "linear-gradient(145deg, rgba(255,255,255,0.98), rgba(225,240,255,0.90))",

  boxShadow:
    "0 15px 40px rgba(55,125,190,0.18)",

  backdropFilter: "blur(8px)",

  overflow: "hidden",

};


const landingLogo = {

  width: "280px",

  height: "135px",

  objectFit: "contain",

  display: "block",

  filter:
    "drop-shadow(0 8px 15px rgba(40,100,160,0.20))",

};


const landingTitle = {

  margin: "8px 0 0",

  fontSize: "48px",

  fontWeight: "800",

  letterSpacing: "-1.5px",

  color: "#173B68",

};


const landingTitleAccent = {

  color: "#4A90E2",

};


const landingSlogan = {

  margin: "18px 0 0",

  fontSize: "28px",

  lineHeight: "1.3",

  fontWeight: "700",

  color: "#263B5A",

};


const landingDescription = {

  maxWidth: "560px",

  margin: "18px auto 0",

  fontSize: "16px",

  lineHeight: "1.7",

  color: "#526579",

};


const landingButton = {

  marginTop: "30px",

  padding: "14px 26px",

  display: "inline-flex",

  alignItems: "center",

  justifyContent: "center",

  gap: "12px",

  border: "none",

  borderRadius: "30px",

  background:
    "linear-gradient(135deg, #64B5F6, #1976D2)",

  color: "#FFFFFF",

  fontSize: "16px",

  fontWeight: "700",

  cursor: "pointer",

  boxShadow:
    "0 8px 22px rgba(30,136,229,0.30)",

  transition:
    "all 0.25s ease",

};


const landingFooter = {

  marginTop: "28px",

  display: "flex",

  justifyContent: "center",

  alignItems: "center",

  gap: "10px",

  fontSize: "12px",

  color: "#78909C",

  letterSpacing: "0.3px",

};


// =========================================================
// EMOCIONES FLOTANTES
// =========================================================

const emotion = {

  position: "absolute",

  zIndex: 2,

  width: "65px",

  height: "65px",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  borderRadius: "50%",

  background:
    "rgba(255,255,255,0.65)",

  border:
    "1px solid rgba(255,255,255,0.9)",

  boxShadow:
    "0 12px 30px rgba(60,120,180,0.12)",

  backdropFilter: "blur(8px)",

  fontSize: "32px",

};


const emotionSmall = {

  position: "absolute",

  zIndex: 1,

  width: "48px",

  height: "48px",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  borderRadius: "50%",

  background:
    "rgba(255,255,255,0.45)",

  boxShadow:
    "0 8px 20px rgba(60,120,180,0.10)",

  fontSize: "24px",

};


// =========================================================
// LUCES DECORATIVAS
// =========================================================

const glowOne = {

  position: "absolute",

  width: "400px",

  height: "400px",

  borderRadius: "50%",

  background:
    "rgba(100,181,246,0.16)",

  filter: "blur(70px)",

  top: "-180px",

  left: "-120px",

};


const glowTwo = {

  position: "absolute",

  width: "350px",

  height: "350px",

  borderRadius: "50%",

  background:
    "rgba(129,199,132,0.12)",

  filter: "blur(70px)",

  bottom: "-150px",

  right: "-100px",

};


export default MainApp;