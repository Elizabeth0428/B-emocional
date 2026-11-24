// src/views/LoginView.jsx

import React, {
  useState
} from "react";

import {
  login
} from "../services/AuthService";

import {
  FaLock,
  FaEye,
  FaEyeSlash
} from "react-icons/fa";

import LogoMirrorSoul from "../components/public/LogoMirrorSoul";


const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;


// ============================================================
// LOGIN
// ============================================================

const LoginView = ({
  onLoginSuccess,
  onBack
}) => {

  const [
    identificador,
    setIdentificador
  ] =
    useState("");


  const [
    password,
    setPassword
  ] =
    useState("");


  const [
    mostrarPassword,
    setMostrarPassword
  ] =
    useState(false);


  const [
    error,
    setError
  ] =
    useState("");


  const [
    loading,
    setLoading
  ] =
    useState(false);


  // ==========================================================
  // CAMBIO OBLIGATORIO DE CONTRASEÑA
  // ==========================================================

  const [
    requiereCambio,
    setRequiereCambio
  ] =
    useState(false);


  const [
    nuevaPassword,
    setNuevaPassword
  ] =
    useState("");


  const [
    confirmarPassword,
    setConfirmarPassword
  ] =
    useState("");


  const [
    mostrarNuevaPassword,
    setMostrarNuevaPassword
  ] =
    useState(false);


  const [
    mostrarConfirmarPassword,
    setMostrarConfirmarPassword
  ] =
    useState(false);


  const [
    usuarioTemporal,
    setUsuarioTemporal
  ] =
    useState(null);


  const [
    tokenTemporal,
    setTokenTemporal
  ] =
    useState(null);


  // ==========================================================
  // LOGIN
  // ==========================================================

  const handleLogin =
    async () => {

      setError("");


      if (
        !identificador ||
        !password
      ) {

        setError(
          "Por favor ingresa tu correo o matrícula y contraseña"
        );

        return;

      }


      setLoading(true);


      try {

        const data =
          await login(
            identificador,
            password
          );


        if (
          !data ||
          !data.user ||
          !data.token
        ) {

          throw new Error(
            "Respuesta inesperada del servidor"
          );

        }


        // ======================================================
        // CONTRASEÑA TEMPORAL
        // ======================================================

        const debeCambiar =
          data
            .requiere_cambio_password ===
            true ||
          Number(
            data.user
              ?.debe_cambiar_password
          ) === 1;


        if (
          debeCambiar
        ) {

          setUsuarioTemporal(
            data.user
          );


          setTokenTemporal(
            data.token
          );


          setRequiereCambio(
            true
          );


          return;

        }


        // ======================================================
        // LOGIN NORMAL
        // ======================================================

        localStorage.setItem(
          "authToken",
          data.token
        );


        localStorage.setItem(
          "user",
          JSON.stringify(
            data.user
          )
        );


        onLoginSuccess({
          ...data.user,
          token:
            data.token
        });


      } catch (
        err
      ) {

        setError(
          err.message ||
          "Error al iniciar sesión"
        );


      } finally {

        setLoading(false);

      }

    };


  // ==========================================================
  // CAMBIAR CONTRASEÑA TEMPORAL
  // ==========================================================

  const handleCambiarPassword =
    async () => {

      setError("");


      if (
        !nuevaPassword ||
        !confirmarPassword
      ) {

        setError(
          "Completa la nueva contraseña y su confirmación"
        );

        return;

      }


      if (
        nuevaPassword.length < 6
      ) {

        setError(
          "La nueva contraseña debe tener al menos 6 caracteres"
        );

        return;

      }


      if (
        nuevaPassword !==
        confirmarPassword
      ) {

        setError(
          "Las contraseñas no coinciden"
        );

        return;

      }


      if (
        nuevaPassword ===
        password
      ) {

        setError(
          "La nueva contraseña debe ser diferente a la contraseña temporal"
        );

        return;

      }


      if (
        !tokenTemporal ||
        !usuarioTemporal
      ) {

        setError(
          "La sesión temporal expiró. Inicia sesión nuevamente."
        );

        return;

      }


      setLoading(true);


      try {

        const response =
          await fetch(
            `${API_URL}/api/change-password`,
            {

              method:
                "PUT",

              headers: {

                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${tokenTemporal}`

              },

              body:
                JSON.stringify({

                  oldPassword:
                    password,

                  newPassword:
                    nuevaPassword

                })

            }
          );


        const data =
          await response
            .json()
            .catch(
              () => ({})
            );


        if (
          !response.ok
        ) {

          throw new Error(
            data.message ||
            "No se pudo cambiar la contraseña"
          );

        }


        const usuarioActualizado = {

          ...usuarioTemporal,

          debe_cambiar_password:
            0

        };


        localStorage.setItem(
          "authToken",
          tokenTemporal
        );


        localStorage.setItem(
          "user",
          JSON.stringify(
            usuarioActualizado
          )
        );


        onLoginSuccess({

          ...usuarioActualizado,

          token:
            tokenTemporal

        });


      } catch (
        err
      ) {

        setError(
          err.message ||
          "Error al cambiar contraseña"
        );


      } finally {

        setLoading(false);

      }

    };


  // ==========================================================
  // CAMBIO OBLIGATORIO
  // ==========================================================

  if (
    requiereCambio
  ) {

    return (

      <div style={styles.page}>

        <div style={styles.glowOne} />
        <div style={styles.glowTwo} />

        <div style={styles.loginShell}>

          <div style={styles.logoArea}>
            <LogoMirrorSoul
              width={150}
              height={96}
              borderRadius={24}
              padding={14}
            />
          </div>

          <div style={styles.iconCircle}>
            <FaLock
              size={24}
              color="#71e7ff"
            />
          </div>

          <h2 style={styles.title}>
            Crea tu nueva contraseña
          </h2>

          <p style={styles.description}>
            Hola{" "}
            <strong style={styles.highlightText}>
              {usuarioTemporal
                ?.nombre ||
                "usuario"}
            </strong>.
            <br />
            Por seguridad debes cambiar
            la contraseña temporal antes
            de continuar.
          </p>


          {usuarioTemporal
            ?.matricula && (

            <div style={styles.matriculaBox}>
              <span style={styles.matriculaLabel}>
                Matrícula
              </span>

              <strong style={styles.matriculaValue}>
                {
                  usuarioTemporal
                    .matricula
                }
              </strong>
            </div>

          )}


          <div style={styles.inputGroup}>
            <label style={styles.label}>
              Nueva contraseña
            </label>

            <div style={styles.inputWrapper}>
              <input
                type={
                  mostrarNuevaPassword
                    ? "text"
                    : "password"
                }
                placeholder="Ingresa tu nueva contraseña"
                value={
                  nuevaPassword
                }
                onChange={
                  e =>
                    setNuevaPassword(
                      e.target.value
                    )
                }
                style={styles.input}
                autoComplete="new-password"
              />

              <button
                type="button"
                style={styles.eyeButton}
                onClick={() =>
                  setMostrarNuevaPassword(
                    !mostrarNuevaPassword
                  )
                }
              >
                {mostrarNuevaPassword
                  ? <FaEyeSlash />
                  : <FaEye />}
              </button>
            </div>
          </div>


          <div style={styles.inputGroup}>
            <label style={styles.label}>
              Confirmar contraseña
            </label>

            <div style={styles.inputWrapper}>
              <input
                type={
                  mostrarConfirmarPassword
                    ? "text"
                    : "password"
                }
                placeholder="Confirma tu nueva contraseña"
                value={
                  confirmarPassword
                }
                onChange={
                  e =>
                    setConfirmarPassword(
                      e.target.value
                    )
                }
                onKeyDown={
                  e => {

                    if (
                      e.key ===
                      "Enter"
                    ) {

                      handleCambiarPassword();

                    }

                  }
                }
                style={styles.input}
                autoComplete="new-password"
              />

              <button
                type="button"
                style={styles.eyeButton}
                onClick={() =>
                  setMostrarConfirmarPassword(
                    !mostrarConfirmarPassword
                  )
                }
              >
                {mostrarConfirmarPassword
                  ? <FaEyeSlash />
                  : <FaEye />}
              </button>
            </div>
          </div>


          <button
            type="button"
            onClick={
              handleCambiarPassword
            }
            style={styles.primaryButton}
            disabled={
              loading
            }
          >

            {loading
              ? "Guardando..."
              : "Crear nueva contraseña"}

          </button>


          {error && (

            <div style={styles.errorBox}>
              {error}
            </div>

          )}

        </div>
      </div>

    );

  }


  // ==========================================================
  // LOGIN NORMAL
  // ==========================================================

  return (

    <div style={styles.page}>

      <div style={styles.glowOne} />
      <div style={styles.glowTwo} />

      <div style={styles.pattern} />

      <div style={styles.loginShell}>

        {/* ============================= */}
        {/* LOGO */}
        {/* ============================= */}

        <div style={styles.logoArea}>
          <LogoMirrorSoul
            width={160}
            height={100}
            borderRadius={24}
            padding={14}
          />
        </div>


        {/* ============================= */}
        {/* TEXTOS */}
        {/* ============================= */}

        <span style={styles.eyebrow}>
          ACCESO MIRRORSOUL
        </span>

        <h1 style={styles.title}>
          Bienvenido de nuevo
        </h1>

        <p style={styles.description}>
          Administradores ingresan con
          correo electrónico.
          <br />
          Usuarios ingresan con su matrícula.
        </p>


        {/* ============================= */}
        {/* IDENTIFICADOR */}
        {/* ============================= */}

        <div style={styles.inputGroup}>
          <label style={styles.label}>
            Correo o matrícula
          </label>

          <div style={styles.inputWrapper}>
            <input
              type="text"
              placeholder="Ingresa tu correo o matrícula"
              value={
                identificador
              }
              onChange={
                e =>
                  setIdentificador(
                    e.target.value
                  )
              }
              style={styles.input}
              autoComplete="username"
            />
          </div>
        </div>


        {/* ============================= */}
        {/* CONTRASEÑA */}
        {/* ============================= */}

        <div style={styles.inputGroup}>
          <label style={styles.label}>
            Contraseña
          </label>

          <div style={styles.inputWrapper}>
            <input
              type={
                mostrarPassword
                  ? "text"
                  : "password"
              }
              placeholder="Ingresa tu contraseña"
              value={
                password
              }
              onChange={
                e =>
                  setPassword(
                    e.target.value
                  )
              }
              onKeyDown={
                e => {

                  if (
                    e.key ===
                    "Enter"
                  ) {

                    handleLogin();

                  }

                }
              }
              style={styles.input}
              autoComplete="current-password"
            />

            <button
              type="button"
              style={styles.eyeButton}
              onClick={() =>
                setMostrarPassword(
                  !mostrarPassword
                )
              }
              aria-label={
                mostrarPassword
                  ? "Ocultar contraseña"
                  : "Mostrar contraseña"
              }
            >
              {mostrarPassword
                ? <FaEyeSlash />
                : <FaEye />}
            </button>
          </div>
        </div>


        {/* ============================= */}
        {/* BOTÓN LOGIN */}
        {/* ============================= */}

        <button
          type="button"
          onClick={
            handleLogin
          }
          style={styles.primaryButton}
          disabled={
            loading
          }
        >

          {loading
            ? "Ingresando..."
            : "Iniciar sesión"}

        </button>


        {/* ============================= */}
        {/* VOLVER */}
        {/* ============================= */}

        <button
          type="button"
          onClick={
            onBack
          }
          style={styles.backButton}
        >
          <span style={styles.backArrow}>
            ←
          </span>

          Volver
        </button>


        {/* ============================= */}
        {/* ERROR */}
        {/* ============================= */}

        {error && (

          <div style={styles.errorBox}>
            {error}
          </div>

        )}

      </div>

    </div>

  );

};


// ============================================================
// ESTILOS
// ============================================================

const styles = {

  page: {
    position: "relative",

    minHeight: "100vh",

    width: "100%",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    padding:
      "50px 20px",

    boxSizing: "border-box",

    overflow: "hidden",

    background:
      "radial-gradient(circle at 14% 20%, rgba(84,220,255,0.11), transparent 26%), radial-gradient(circle at 86% 76%, rgba(143,121,255,0.11), transparent 28%), linear-gradient(180deg, #06111d 0%, #091827 55%, #06111d 100%)",

    fontFamily:
      "'Inter', 'Segoe UI', Arial, sans-serif",
  },


  glowOne: {
    position: "absolute",

    width: "440px",

    height: "440px",

    borderRadius: "50%",

    top: "-160px",

    left: "-130px",

    background:
      "rgba(75,216,255,0.07)",

    filter:
      "blur(100px)",

    pointerEvents: "none",
  },


  glowTwo: {
    position: "absolute",

    width: "480px",

    height: "480px",

    borderRadius: "50%",

    right: "-160px",

    bottom: "-180px",

    background:
      "rgba(143,121,255,0.08)",

    filter:
      "blur(110px)",

    pointerEvents: "none",
  },


  pattern: {
    position: "absolute",

    inset: 0,

    opacity: 0.25,

    pointerEvents: "none",

    backgroundImage:
      "radial-gradient(circle, rgba(99,224,255,0.18) 1px, transparent 1px)",

    backgroundSize:
      "46px 46px",
  },


  loginShell: {
    position: "relative",

    zIndex: 3,

    width: "100%",

    maxWidth: "500px",

    padding:
      "38px 38px 36px",

    boxSizing: "border-box",

    borderRadius: "30px",

    background:
      "linear-gradient(145deg, rgba(13,27,43,0.96), rgba(7,16,28,0.98))",

    border:
      "1px solid rgba(255,255,255,0.08)",

    boxShadow:
      "0 35px 90px rgba(0,0,0,0.38)",

    backdropFilter:
      "blur(20px)",

    WebkitBackdropFilter:
      "blur(20px)",

    textAlign: "center",
  },


  logoArea: {
    display: "flex",

    justifyContent: "center",

    marginBottom: "24px",
  },


  eyebrow: {
    display: "inline-block",

    marginBottom: "10px",

    color: "#72e9ff",

    fontSize: "13px",

    fontWeight: "900",

    letterSpacing: "2.2px",
  },


  iconCircle: {
    width: "52px",

    height: "52px",

    margin:
      "0 auto 16px",

    borderRadius: "16px",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    background:
      "rgba(89,222,255,0.09)",

    border:
      "1px solid rgba(89,222,255,0.15)",
  },


  title: {
    margin:
      "0 0 14px",

    color: "#ffffff",

    fontSize:
      "clamp(30px, 3vw, 40px)",

    lineHeight: "1.08",

    letterSpacing:
      "-1px",

    fontWeight: "900",
  },


  description: {
    margin:
      "0 auto 28px",

    maxWidth: "410px",

    color:
      "rgba(220,233,247,0.70)",

    fontSize: "15px",

    lineHeight: "1.7",
  },


  highlightText: {
    color: "#ffffff",
  },


  inputGroup: {
    marginBottom: "17px",

    textAlign: "left",
  },


  label: {
    display: "block",

    marginBottom: "8px",

    color:
      "rgba(229,239,249,0.82)",

    fontSize: "14px",

    fontWeight: "800",
  },


  inputWrapper: {
    position: "relative",
  },


  input: {
    width: "100%",

    boxSizing: "border-box",

    minHeight: "54px",

    padding:
      "0 48px 0 16px",

    borderRadius: "14px",

    border:
      "1px solid rgba(255,255,255,0.09)",

    background:
      "rgba(255,255,255,0.045)",

    color: "#ffffff",

    fontSize: "15px",

    outline: "none",

    transition:
      "all 0.2s ease",
  },


  eyeButton: {
    position: "absolute",

    top: "50%",

    right: "14px",

    transform:
      "translateY(-50%)",

    border: "none",

    background:
      "transparent",

    color:
      "rgba(224,235,248,0.66)",

    cursor: "pointer",

    fontSize: "17px",

    padding: "5px",
  },


  primaryButton: {
    width: "100%",

    minHeight: "54px",

    marginTop: "7px",

    border: "none",

    borderRadius: "15px",

    background:
      "linear-gradient(135deg, #61e6ff 0%, #7dc8ff 45%, #8e7cff 100%)",

    color: "#07111f",

    fontSize: "16px",

    fontWeight: "900",

    cursor: "pointer",

    boxShadow:
      "0 15px 34px rgba(95,217,255,0.14)",
  },


  backButton: {
    width: "100%",

    minHeight: "52px",

    marginTop: "12px",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    gap: "8px",

    borderRadius: "15px",

    border:
      "1px solid rgba(255,255,255,0.09)",

    background:
      "rgba(255,255,255,0.035)",

    color:
      "rgba(235,243,251,0.86)",

    fontSize: "15px",

    fontWeight: "800",

    cursor: "pointer",
  },


  backArrow: {
    color: "#72e9ff",

    fontSize: "19px",

    fontWeight: "900",
  },


  matriculaBox: {
    display: "flex",

    justifyContent:
      "space-between",

    alignItems: "center",

    padding:
      "13px 15px",

    marginBottom:
      "20px",

    borderRadius:
      "14px",

    background:
      "rgba(142,124,255,0.08)",

    border:
      "1px solid rgba(142,124,255,0.16)",
  },


  matriculaLabel: {
    color:
      "rgba(220,233,247,0.70)",

    fontSize:
      "13px",

    fontWeight:
      "700",
  },


  matriculaValue: {
    color:
      "#ffffff",

    fontSize:
      "15px",

    fontWeight:
      "900",
  },


  errorBox: {
    marginTop: "16px",

    padding:
      "12px 14px",

    borderRadius:
      "13px",

    background:
      "rgba(255,77,97,0.09)",

    border:
      "1px solid rgba(255,77,97,0.18)",

    color:
      "#ffadb6",

    fontSize:
      "14px",

    fontWeight:
      "700",

    lineHeight:
      "1.5",
  },

};


export default LoginView;