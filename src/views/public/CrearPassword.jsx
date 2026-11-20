// ============================================================
// src/views/public/CrearPassword.jsx
// ============================================================

import React, {
  useEffect,
  useState,
} from "react";

import {
  useNavigate,
  useSearchParams,
} from "react-router-dom";

import LogoMirrorSoul from "../../components/public/LogoMirrorSoul.jsx";


// ============================================================
// API
// ============================================================

const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://www.reflejoyalma.com";


// ============================================================
// VISTA
// ============================================================

export default function CrearPassword() {

  const navigate =
    useNavigate();


  const [
    searchParams
  ] =
    useSearchParams();


  const token =
    searchParams.get(
      "token"
    ) || "";


  // ==========================================================
  // ESTADOS
  // ==========================================================

  const [
    cargando,
    setCargando
  ] =
    useState(
      true
    );


  const [
    valido,
    setValido
  ] =
    useState(
      false
    );


  const [
    usuario,
    setUsuario
  ] =
    useState(
      null
    );


  const [
    password,
    setPassword
  ] =
    useState(
      ""
    );


  const [
    confirmarPassword,
    setConfirmarPassword
  ] =
    useState(
      ""
    );


  const [
    mostrarPassword,
    setMostrarPassword
  ] =
    useState(
      false
    );


  const [
    mostrarConfirmar,
    setMostrarConfirmar
  ] =
    useState(
      false
    );


  const [
    guardando,
    setGuardando
  ] =
    useState(
      false
    );


  const [
    mensaje,
    setMensaje
  ] =
    useState(
      ""
    );


  const [
    error,
    setError
  ] =
    useState(
      ""
    );


  const [
    terminado,
    setTerminado
  ] =
    useState(
      false
    );


  // ==========================================================
  // VALIDAR TOKEN
  // ==========================================================

  useEffect(
    () => {

      async function validarToken() {

        try {

          setCargando(
            true
          );


          setError(
            ""
          );


          if (
            !token
          ) {

            setValido(
              false
            );


            setError(
              "El enlace de acceso no contiene un token válido."
            );


            return;

          }


          const response =
            await fetch(
              `${API_URL}/api/auth/password-inicial/validar/${encodeURIComponent(
                token
              )}`
            );


          const data =
            await response.json();


          if (
            !response.ok ||
            !data.ok ||
            !data.valido
          ) {

            setValido(
              false
            );


            setError(
              data.message ||
              "El enlace no es válido o ya expiró."
            );


            return;

          }


          setUsuario(
            data.usuario ||
            null
          );


          setValido(
            true
          );


        } catch (
          err
        ) {

          console.error(
            "Error validando token:",
            err
          );


          setValido(
            false
          );


          setError(
            "No fue posible validar el enlace. Intenta nuevamente."
          );


        } finally {

          setCargando(
            false
          );

        }

      }


      validarToken();

    },
    [
      token
    ]
  );


  // ==========================================================
  // REGLAS PASSWORD
  // ==========================================================

  const tieneLongitud =
    password.length >=
    8;


  const tieneMayuscula =
    /[A-Z]/.test(
      password
    );


  const tieneMinuscula =
    /[a-z]/.test(
      password
    );


  const tieneNumero =
    /[0-9]/.test(
      password
    );


  const passwordsCoinciden =
    password.length > 0 &&
    password ===
      confirmarPassword;


  const passwordValido =
    tieneLongitud &&
    tieneMayuscula &&
    tieneMinuscula &&
    tieneNumero &&
    passwordsCoinciden;


  // ==========================================================
  // CREAR PASSWORD
  // ==========================================================

  async function handleSubmit(
    e
  ) {

    e.preventDefault();


    if (
      guardando
    ) {

      return;

    }


    setError(
      ""
    );


    setMensaje(
      ""
    );


    if (
      !passwordValido
    ) {

      setError(
        "Revisa los requisitos de la contraseña."
      );


      return;

    }


    try {

      setGuardando(
        true
      );


      const response =
        await fetch(
          `${API_URL}/api/auth/password-inicial/crear`,
          {
            method:
              "POST",

            headers: {
              "Content-Type":
                "application/json",
            },

            body:
              JSON.stringify({
                token,

                password,

                confirmar_password:
                  confirmarPassword,
              }),
          }
        );


      const data =
        await response.json();


      if (
        !response.ok ||
        !data.ok
      ) {

        setError(
          data.message ||
          "No fue posible crear tu contraseña."
        );


        return;

      }


      setTerminado(
        true
      );


      setMensaje(
        "Tu contraseña fue creada correctamente."
      );


      setPassword(
        ""
      );


      setConfirmarPassword(
        ""
      );


    } catch (
      err
    ) {

      console.error(
        "Error creando contraseña:",
        err
      );


      setError(
        "No fue posible conectar con MirrorSoul. Intenta nuevamente."
      );


    } finally {

      setGuardando(
        false
      );

    }

  }


  // ==========================================================
  // CARGANDO
  // ==========================================================

  if (
    cargando
  ) {

    return (
      <div style={styles.page}>

        <div style={styles.backgroundGlowOne} />
        <div style={styles.backgroundGlowTwo} />

        <div style={styles.card}>

          <div style={styles.logoCard}>
            <LogoMirrorSoul />
          </div>

          <h1 style={styles.title}>
            MirrorSoul
          </h1>

          <p style={styles.loadingText}>
            Validando tu enlace de acceso...
          </p>

          <div style={styles.loader} />

        </div>

      </div>
    );

  }


  // ==========================================================
  // TOKEN INVÁLIDO
  // ==========================================================

  if (
    !valido &&
    !terminado
  ) {

    return (
      <div style={styles.page}>

        <div style={styles.backgroundGlowOne} />
        <div style={styles.backgroundGlowTwo} />

        <div style={styles.card}>

          <div style={styles.logoCard}>
            <LogoMirrorSoul />
          </div>

          <div style={styles.errorIcon}>
            !
          </div>

          <h1 style={styles.title}>
            Enlace no disponible
          </h1>

          <p style={styles.description}>
            {error}
          </p>

          <p style={styles.secondaryText}>
            El enlace pudo haber expirado,
            haber sido utilizado anteriormente
            o no ser válido.
          </p>

          <button
            type="button"
            style={styles.primaryButton}
            onClick={() =>
              navigate(
                "/login"
              )
            }
          >
            Ir a iniciar sesión
          </button>

        </div>

      </div>
    );

  }


  // ==========================================================
  // PASSWORD CREADO
  // ==========================================================

  if (
    terminado
  ) {

    return (
      <div style={styles.page}>

        <div style={styles.backgroundGlowOne} />
        <div style={styles.backgroundGlowTwo} />

        <div style={styles.card}>

          <div style={styles.logoCard}>
            <LogoMirrorSoul />
          </div>

          <div style={styles.successIcon}>
            ✓
          </div>

          <p style={styles.badge}>
            CUENTA ACTIVADA
          </p>

          <h1 style={styles.title}>
            ¡Todo listo!
          </h1>

          <p style={styles.description}>
            {mensaje}
          </p>

          <p style={styles.secondaryText}>
            Tu cuenta de MirrorSoul ya está
            preparada. Ahora puedes iniciar
            sesión con tu correo y la contraseña
            que acabas de crear.
          </p>

          <button
            type="button"
            style={styles.primaryButton}
            onClick={() =>
              navigate(
                "/login"
              )
            }
          >
            Iniciar sesión
          </button>

        </div>

      </div>
    );

  }


  // ==========================================================
  // FORMULARIO
  // ==========================================================

  return (
    <div style={styles.page}>

      <div style={styles.backgroundGlowOne} />
      <div style={styles.backgroundGlowTwo} />


      <div style={styles.container}>

        {/* ==================================================
            LADO IZQUIERDO
        ================================================== */}

        <div style={styles.brandSide}>

          <div style={styles.brandLogo}>
            <LogoMirrorSoul />
          </div>

          <p style={styles.brandBadge}>
            MIRRORSOUL
          </p>

          <h2 style={styles.brandTitle}>
            Bienvenido a tu
            <br />
            nueva cuenta
          </h2>

          <p style={styles.brandDescription}>
            Tu suscripción ya fue activada.
            Solo falta crear una contraseña
            segura para comenzar a utilizar
            MirrorSoul.
          </p>


          <div style={styles.infoBox}>

            <div style={styles.infoTitle}>
              Tu cuenta
            </div>

            <div style={styles.infoValue}>
              {usuario?.nombre ||
              "Administrador"}
            </div>

            <div style={styles.infoEmail}>
              {usuario?.correo ||
              ""}
            </div>

          </div>

        </div>


        {/* ==================================================
            FORMULARIO
        ================================================== */}

        <div style={styles.formSide}>

          <p style={styles.smallBadge}>
            ACCESO SEGURO
          </p>

          <h1 style={styles.formTitle}>
            Crea tu contraseña
          </h1>

          <p style={styles.formDescription}>
            Esta será la contraseña que utilizarás
            para entrar a tu cuenta de MirrorSoul.
          </p>


          <form
            onSubmit={
              handleSubmit
            }
          >

            {/* ==================================================
                PASSWORD
            ================================================== */}

            <label style={styles.label}>
              Nueva contraseña
            </label>

            <div style={styles.inputWrapper}>

              <input
                type={
                  mostrarPassword
                    ? "text"
                    : "password"
                }
                value={
                  password
                }
                onChange={
                  (
                    e
                  ) =>
                    setPassword(
                      e.target.value
                    )
                }
                placeholder="Escribe tu contraseña"
                autoComplete="new-password"
                style={styles.input}
              />

              <button
                type="button"
                onClick={() =>
                  setMostrarPassword(
                    !mostrarPassword
                  )
                }
                style={styles.eyeButton}
              >
                {mostrarPassword
                  ? "Ocultar"
                  : "Ver"}
              </button>

            </div>


            {/* ==================================================
                CONFIRMAR
            ================================================== */}

            <label style={styles.label}>
              Confirmar contraseña
            </label>

            <div style={styles.inputWrapper}>

              <input
                type={
                  mostrarConfirmar
                    ? "text"
                    : "password"
                }
                value={
                  confirmarPassword
                }
                onChange={
                  (
                    e
                  ) =>
                    setConfirmarPassword(
                      e.target.value
                    )
                }
                placeholder="Repite tu contraseña"
                autoComplete="new-password"
                style={styles.input}
              />

              <button
                type="button"
                onClick={() =>
                  setMostrarConfirmar(
                    !mostrarConfirmar
                  )
                }
                style={styles.eyeButton}
              >
                {mostrarConfirmar
                  ? "Ocultar"
                  : "Ver"}
              </button>

            </div>


            {/* ==================================================
                REQUISITOS
            ================================================== */}

            <div style={styles.requirementsBox}>

              <p style={styles.requirementsTitle}>
                Tu contraseña debe contener:
              </p>

              <Requirement
                ok={
                  tieneLongitud
                }
                text="Mínimo 8 caracteres"
              />

              <Requirement
                ok={
                  tieneMayuscula
                }
                text="Una letra mayúscula"
              />

              <Requirement
                ok={
                  tieneMinuscula
                }
                text="Una letra minúscula"
              />

              <Requirement
                ok={
                  tieneNumero
                }
                text="Un número"
              />

              <Requirement
                ok={
                  passwordsCoinciden
                }
                text="Las contraseñas coinciden"
              />

            </div>


            {/* ==================================================
                ERROR
            ================================================== */}

            {error && (
              <div style={styles.alertError}>
                {error}
              </div>
            )}


            {/* ==================================================
                BOTÓN
            ================================================== */}

            <button
              type="submit"
              disabled={
                !passwordValido ||
                guardando
              }
              style={{
                ...styles.primaryButton,

                ...(
                  !passwordValido ||
                  guardando
                    ? styles.disabledButton
                    : {}
                ),
              }}
            >
              {guardando
                ? "Guardando..."
                : "Crear contraseña"}
            </button>


            <p style={styles.securityText}>
              🔒 Tu contraseña se almacena cifrada
              y nunca se envía por correo.
            </p>

          </form>

        </div>

      </div>

    </div>
  );

}


// ============================================================
// COMPONENTE REQUISITO
// ============================================================

function Requirement({
  ok,
  text,
}) {

  return (
    <div style={styles.requirement}>

      <span
        style={{
          ...styles.requirementIcon,

          background:
            ok
              ? "#dcfce7"
              : "#f1f5f9",

          color:
            ok
              ? "#15803d"
              : "#64748b",
        }}
      >
        {ok
          ? "✓"
          : "•"}
      </span>

      <span
        style={{
          color:
            ok
              ? "#166534"
              : "#64748b",
        }}
      >
        {text}
      </span>

    </div>
  );

}


// ============================================================
// ESTILOS
// ============================================================

const styles = {

  page: {
    minHeight:
      "100vh",

    background:
      "linear-gradient(135deg, #07111f 0%, #101b32 45%, #111827 100%)",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    padding:
      "35px 20px",

    position:
      "relative",

    overflow:
      "hidden",

    fontFamily:
      "'Inter', 'Segoe UI', Arial, sans-serif",
  },


  backgroundGlowOne: {
    position:
      "absolute",

    width:
      "520px",

    height:
      "520px",

    borderRadius:
      "50%",

    background:
      "rgba(75, 85, 255, 0.18)",

    filter:
      "blur(100px)",

    top:
      "-220px",

    right:
      "-100px",
  },


  backgroundGlowTwo: {
    position:
      "absolute",

    width:
      "520px",

    height:
      "520px",

    borderRadius:
      "50%",

    background:
      "rgba(14, 165, 233, 0.10)",

    filter:
      "blur(120px)",

    bottom:
      "-220px",

    left:
      "-120px",
  },


  // ==========================================================
  // CONTENEDOR PRINCIPAL
  // ==========================================================

  container: {
    width:
      "100%",

    maxWidth:
      "1250px",

    minHeight:
      "720px",

    display:
      "grid",

    gridTemplateColumns:
      "minmax(380px, 0.85fr) minmax(520px, 1.15fr)",

    background:
      "#ffffff",

    borderRadius:
      "32px",

    overflow:
      "hidden",

    boxShadow:
      "0 35px 100px rgba(0,0,0,0.35)",

    position:
      "relative",

    zIndex:
      2,
  },


  // ==========================================================
  // LADO IZQUIERDO
  // ==========================================================

  brandSide: {
    background:
      "linear-gradient(160deg, #111827 0%, #172554 100%)",

    padding:
      "60px 52px",

    color:
      "#ffffff",

    display:
      "flex",

    flexDirection:
      "column",

    justifyContent:
      "center",
  },


  brandLogo: {
    width:
      "280px",

    maxWidth:
      "100%",

    marginBottom:
      "28px",

    background:
      "rgba(255,255,255,0.04)",

    border:
      "1px solid rgba(255,255,255,0.08)",

    borderRadius:
      "18px",

    padding:
      "15px",
  },


  brandBadge: {
    margin:
      "0 0 16px",

    fontSize:
      "13px",

    letterSpacing:
      "5px",

    fontWeight:
      "800",

    color:
      "#7dd3fc",
  },


  brandTitle: {
    margin:
      "0",

    fontSize:
      "44px",

    lineHeight:
      "1.08",

    fontWeight:
      "900",
  },


  brandDescription: {
    fontSize:
      "18px",

    lineHeight:
      "1.8",

    color:
      "#dbeafe",

    marginTop:
      "25px",

    maxWidth:
      "430px",
  },


  infoBox: {
    marginTop:
      "45px",

    border:
      "1px solid rgba(255,255,255,.14)",

    background:
      "rgba(255,255,255,.06)",

    borderRadius:
      "20px",

    padding:
      "24px",
  },


  infoTitle: {
    color:
      "#93c5fd",

    fontSize:
      "12px",

    textTransform:
      "uppercase",

    letterSpacing:
      "2px",

    marginBottom:
      "10px",
  },


  infoValue: {
    fontSize:
      "18px",

    fontWeight:
      "800",
  },


  infoEmail: {
    marginTop:
      "6px",

    color:
      "#dbeafe",

    fontSize:
      "14px",

    wordBreak:
      "break-word",
  },


  // ==========================================================
  // FORMULARIO
  // ==========================================================

  formSide: {
    padding:
      "65px",

    background:
      "#ffffff",

    display:
      "flex",

    flexDirection:
      "column",

    justifyContent:
      "center",
  },


  smallBadge: {
    color:
      "#4f46e5",

    fontWeight:
      "900",

    fontSize:
      "12px",

    letterSpacing:
      "3px",

    margin:
      "0 0 12px",
  },


  formTitle: {
    margin:
      "0",

    color:
      "#0f172a",

    fontSize:
      "42px",

    lineHeight:
      "1.1",

    fontWeight:
      "900",
  },


  formDescription: {
    color:
      "#64748b",

    lineHeight:
      "1.7",

    fontSize:
      "17px",

    margin:
      "16px 0 28px",
  },


  label: {
    display:
      "block",

    color:
      "#1e293b",

    fontSize:
      "14px",

    fontWeight:
      "800",

    marginBottom:
      "8px",

    marginTop:
      "18px",
  },


  inputWrapper: {
    display:
      "flex",

    alignItems:
      "center",

    border:
      "1px solid #cbd5e1",

    borderRadius:
      "14px",

    overflow:
      "hidden",

    background:
      "#ffffff",

    minHeight:
      "58px",

    transition:
      "border .2s ease",
  },


  input: {
    flex:
      1,

    border:
      "none",

    outline:
      "none",

    padding:
      "0 18px",

    fontSize:
      "16px",

    color:
      "#0f172a",

    minWidth:
      0,

    background:
      "transparent",
  },


  eyeButton: {
    border:
      "none",

    background:
      "transparent",

    color:
      "#4f46e5",

    fontWeight:
      "800",

    cursor:
      "pointer",

    padding:
      "0 18px",

    height:
      "56px",
  },


  // ==========================================================
  // REQUISITOS
  // ==========================================================

  requirementsBox: {
    background:
      "#f8fafc",

    border:
      "1px solid #e2e8f0",

    borderRadius:
      "16px",

    padding:
      "20px",

    marginTop:
      "25px",
  },


  requirementsTitle: {
    margin:
      "0 0 14px",

    fontWeight:
      "800",

    fontSize:
      "13px",

    color:
      "#334155",
  },


  requirement: {
    display:
      "flex",

    alignItems:
      "center",

    gap:
      "10px",

    fontSize:
      "13px",

    margin:
      "8px 0",
  },


  requirementIcon: {
    width:
      "23px",

    height:
      "23px",

    borderRadius:
      "50%",

    display:
      "inline-flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    fontWeight:
      "900",

    flexShrink:
      0,
  },


  // ==========================================================
  // ALERTAS
  // ==========================================================

  alertError: {
    marginTop:
      "18px",

    padding:
      "14px 16px",

    borderRadius:
      "12px",

    background:
      "#fef2f2",

    color:
      "#b91c1c",

    border:
      "1px solid #fecaca",

    fontSize:
      "14px",

    lineHeight:
      "1.5",
  },


  // ==========================================================
  // BOTÓN
  // ==========================================================

  primaryButton: {
    width:
      "100%",

    border:
      "none",

    borderRadius:
      "14px",

    padding:
      "17px 20px",

    marginTop:
      "25px",

    background:
      "linear-gradient(135deg, #4f46e5, #2563eb)",

    color:
      "#ffffff",

    fontSize:
      "16px",

    fontWeight:
      "900",

    cursor:
      "pointer",

    boxShadow:
      "0 14px 34px rgba(79,70,229,.25)",
  },


  disabledButton: {
    opacity:
      0.45,

    cursor:
      "not-allowed",

    boxShadow:
      "none",
  },


  securityText: {
    textAlign:
      "center",

    color:
      "#94a3b8",

    fontSize:
      "12px",

    marginTop:
      "16px",
  },


  // ==========================================================
  // TARJETAS CARGANDO / ERROR / ÉXITO
  // ==========================================================

  card: {
    width:
      "100%",

    maxWidth:
      "520px",

    background:
      "#ffffff",

    borderRadius:
      "26px",

    padding:
      "46px 42px",

    textAlign:
      "center",

    boxShadow:
      "0 30px 80px rgba(0,0,0,.30)",

    position:
      "relative",

    zIndex:
      2,
  },


  logoCard: {
    width:
      "260px",

    maxWidth:
      "100%",

    margin:
      "0 auto 25px",

    padding:
      "12px",

    borderRadius:
      "16px",

    background:
      "#0f172a",
  },


  title: {
    color:
      "#0f172a",

    fontSize:
      "32px",

    margin:
      "0 0 15px",

    fontWeight:
      "900",
  },


  description: {
    color:
      "#475569",

    fontSize:
      "17px",

    lineHeight:
      "1.6",
  },


  secondaryText: {
    color:
      "#64748b",

    fontSize:
      "14px",

    lineHeight:
      "1.7",

    marginTop:
      "18px",
  },


  loadingText: {
    color:
      "#64748b",

    marginTop:
      "10px",
  },


  loader: {
    width:
      "38px",

    height:
      "38px",

    margin:
      "25px auto 0",

    border:
      "4px solid #e2e8f0",

    borderTop:
      "4px solid #4f46e5",

    borderRadius:
      "50%",
  },


  errorIcon: {
    width:
      "62px",

    height:
      "62px",

    borderRadius:
      "50%",

    margin:
      "0 auto 20px",

    display:
      "flex",

    justifyContent:
      "center",

    alignItems:
      "center",

    background:
      "#fee2e2",

    color:
      "#dc2626",

    fontWeight:
      "900",

    fontSize:
      "29px",
  },


  successIcon: {
    width:
      "72px",

    height:
      "72px",

    borderRadius:
      "50%",

    margin:
      "0 auto 20px",

    display:
      "flex",

    justifyContent:
      "center",

    alignItems:
      "center",

    background:
      "#dcfce7",

    color:
      "#15803d",

    fontSize:
      "34px",

    fontWeight:
      "900",
  },


  badge: {
    color:
      "#15803d",

    fontWeight:
      "800",

    letterSpacing:
      "2px",

    fontSize:
      "12px",
  },

};