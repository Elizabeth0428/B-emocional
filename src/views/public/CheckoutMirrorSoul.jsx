import React, {

  useEffect,

  useMemo,

  useState,

} from "react";



import {

  useLocation,

  useNavigate,

} from "react-router-dom";



import NavbarPublica from "../../components/public/NavbarPublica.jsx";

import FooterPublico from "../../components/public/FooterPublico.jsx";

import LogoMirrorSoul from "../../components/public/LogoMirrorSoul.jsx";



// ============================================================

// MIRRORSOUL - CHECKOUT

// Diseño modo claro y oscuro

// Se conserva la integración original con Mercado Pago

// ============================================================



const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://www.reflejoyalma.com";



const NOMBRES_PLAN = {

  independiente: "Independiente",

  clinica: "Clínica",

  rh: "Recursos Humanos",

  educativo: "Educativo",

};



// ============================================================

// FORMATEAR PRECIOS

// ============================================================



function formatearPrecio(valor) {

  const numero = Number(valor);



  if (!Number.isFinite(numero)) {

    return "No disponible";

  }



  return new Intl.NumberFormat("es-MX", {

    style: "currency",

    currency: "MXN",

    minimumFractionDigits: 2,

    maximumFractionDigits: 2,

  }).format(numero);

}



// ============================================================

// FILA DE RESUMEN

// ============================================================



function FilaResumen({ label, value }) {

  return (

    <div className="ms-checkout-summary-row">

      <span>{label}</span>

      <strong>{value ?? "—"}</strong>

    </div>

  );

}



// ============================================================

// COMPONENTE PRINCIPAL

// ============================================================



function CheckoutMirrorSoul() {

  const navigate = useNavigate();

  const location = useLocation();



  // ==========================================================

  // 1. PARÁMETROS DE LA URL

  // ==========================================================



  const params = useMemo(

    () => new URLSearchParams(location.search),

    [location.search]

  );



  const planQuery = params.get("plan") || "";



  const periodoQuery =

    params.get("periodo") === "anual"

      ? "anual"

      : "mensual";



  // ==========================================================

  // 2. ESTADOS

  // ==========================================================



  const [datosRegistro, setDatosRegistro] =

    useState(null);



  const [registroCargado, setRegistroCargado] =

    useState(false);



  const [precioPlan, setPrecioPlan] =

    useState(null);



  const [cargandoPrecio, setCargandoPrecio] =

    useState(true);



  const [procesandoPago, setProcesandoPago] =

    useState(false);



  const [error, setError] = useState("");



  // ==========================================================

  // 3. RECUPERAR DATOS DE CONTRATACIÓN

  // ==========================================================



  useEffect(() => {

    try {

      const guardado = sessionStorage.getItem(

        "mirrorsoul_plan_registro"

      );



      if (!guardado) {

        setDatosRegistro(null);

      } else {

        const datos = JSON.parse(guardado);

        setDatosRegistro(datos);

      }

    } catch (err) {

      console.error(

        "Error leyendo datos de contratación:",

        err

      );



      setDatosRegistro(null);

    } finally {

      setRegistroCargado(true);

    }

  }, []);



  // ==========================================================

  // 4. PLAN Y PERIODO DEFINITIVOS

  // ==========================================================



  const tipoPlan =

    datosRegistro?.tipo_plan ||

    datosRegistro?.tipo_organizacion ||

    planQuery;



  const periodo =

    datosRegistro?.periodo_facturacion ||

    periodoQuery;



  const nombrePlan =

    precioPlan?.nombre ||

    NOMBRES_PLAN[tipoPlan] ||

    "MirrorSoul";



  // ==========================================================

  // 5. CONSULTAR PRECIO AL BACKEND

  // NO SE UTILIZAN PRECIOS FIJOS EN EL FRONTEND

  // ==========================================================



  useEffect(() => {

    if (!registroCargado || !datosRegistro) {

      setCargandoPrecio(false);

      return;

    }



    if (!tipoPlan) {

      setPrecioPlan(null);

      setCargandoPrecio(false);

      setError("No se identificó el plan seleccionado.");

      return;

    }



    const controller = new AbortController();



    const cargarPrecio = async () => {

      try {

        setCargandoPrecio(true);

        setPrecioPlan(null);

        setError("");



        const url =

          `${API_URL}/api/pagos/precio` +

          `?plan=${encodeURIComponent(tipoPlan)}` +

          `&periodo=${encodeURIComponent(periodo)}`;



        const response = await fetch(url, {

          signal: controller.signal,

        });



        const data = await response.json();



        if (!response.ok || !data.ok || !data.plan) {

          throw new Error(

            data.message ||

              "No se pudo obtener el precio del plan."

          );

        }



        const precio = Number(data.plan.precio);



        if (

          !Number.isFinite(precio) ||

          precio <= 0

        ) {

          throw new Error(

            "Este plan todavía no tiene un precio válido para contratar."

          );

        }



        if (!controller.signal.aborted) {

          setPrecioPlan(data.plan);

        }

      } catch (err) {

        if (controller.signal.aborted) {

          return;

        }



        console.error(

          "Error consultando precio:",

          err

        );



        setPrecioPlan(null);



        setError(

          err.message ||

            "No fue posible consultar el precio."

        );

      } finally {

        if (!controller.signal.aborted) {

          setCargandoPrecio(false);

        }

      }

    };



    cargarPrecio();



    return () => {

      controller.abort();

    };

  }, [

    registroCargado,

    datosRegistro,

    tipoPlan,

    periodo,

  ]);



  // ==========================================================

  // 6. CONTINUAR CON MERCADO PAGO

  // SE CONSERVA LA INTEGRACIÓN ORIGINAL

  // ==========================================================



  const continuarMercadoPago = async () => {

    if (procesandoPago) {

      return;

    }



    try {

      if (!datosRegistro) {

        throw new Error(

          "No encontramos los datos de contratación."

        );

      }



      if (!datosRegistro.correo) {

        throw new Error(

          "Falta el correo del responsable."

        );

      }



      if (!tipoPlan || !precioPlan) {

        throw new Error(

          "Primero debemos confirmar el precio del plan."

        );

      }


      if (
        tipoPlan === "independiente" &&
        ![
          "clinica",
          "rh",
        ].includes(
          String(
            datosRegistro
              ?.perfil_independiente ||
            ""
          )
            .trim()
            .toLowerCase()
        )
      ) {

        throw new Error(

          "Selecciona si utilizarás el plan Independiente como Psicología/Clínica o Recursos Humanos."

        );

      }



      setProcesandoPago(true);

      setError("");



      // ======================================================

      // MISMOS DATOS DEL CHECKOUT ORIGINAL

      // ======================================================



      const body = {

        tipo_plan:
          tipoPlan,


        periodo_facturacion:
          periodo,


        perfil_independiente:
          datosRegistro
            ?.perfil_independiente ||
          "",


        correo:
          datosRegistro.correo,


        nombre_responsable:
          datosRegistro.nombre_responsable ||
          "",


        nombre_organizacion:
          datosRegistro.nombre_organizacion ||
          "",


        telefono:
          datosRegistro.telefono ||
          "",


        requiere_factura:
          Boolean(
            datosRegistro.requiere_factura
          ),


        rfc:
          datosRegistro.rfc ||
          "",

      };



      // ======================================================

      // CREAR SUSCRIPCIÓN

      // ======================================================



      const response = await fetch(

        `${API_URL}/api/pagos/crear-suscripcion`,

        {

          method: "POST",



          headers: {

            "Content-Type": "application/json",

          },



          body: JSON.stringify(body),

        }

      );



      const data = await response.json();



      if (!response.ok || !data.ok) {

        throw new Error(

          data.message ||

            "No fue posible iniciar el pago."

        );

      }



      // ======================================================

      // OBTENER ENLACE DE MERCADO PAGO

      // ======================================================



      const initPoint =

        data?.mercado_pago?.init_point;



      if (

        typeof initPoint !== "string" ||

        !/^https?:\/\//i.test(initPoint)

      ) {

        throw new Error(

          "Mercado Pago no devolvió un enlace de pago válido."

        );

      }



      // ======================================================

      // GUARDAR REFERENCIA

      // MISMA CLAVE DEL CHECKOUT ORIGINAL

      // ======================================================



      sessionStorage.setItem(

        "mirrorsoul_pago_actual",

        JSON.stringify({

          ...data.mercado_pago,



          plan: data.plan,



          contratacion: data.contratacion,

        })

      );



      // ======================================================

      // REDIRECCIÓN A MERCADO PAGO

      // ======================================================



      window.location.href = initPoint;

    } catch (err) {

      console.error(

        "Error iniciando Mercado Pago:",

        err

      );



      setError(

        err.message ||

          "No se pudo iniciar el pago."

      );



      setProcesandoPago(false);

    }

  };



  // ==========================================================

  // 7. REGRESAR A DATOS

  // ==========================================================



  const regresarARegistro = () => {

    const query = new URLSearchParams({

      plan: tipoPlan,

      periodo,

    });



    const idPlan =

      datosRegistro?.id_plan;



    if (idPlan) {

      query.set("id", String(idPlan));

    }



    navigate(

      `/registro-plan?${query.toString()}`

    );

  };



  // ==========================================================

  // 8. ESTADO DEL TOTAL

  // ==========================================================



  const total =

    cargandoPrecio

      ? "Consultando..."

      : precioPlan

        ? formatearPrecio(precioPlan.precio)

        : "No disponible";



  const puedePagar =

    Boolean(datosRegistro) &&

    Boolean(precioPlan) &&

    !cargandoPrecio &&

    !procesandoPago;



  // ==========================================================

  // 9. ESPERAR LECTURA DE REGISTRO

  // ==========================================================



  if (!registroCargado) {

    return (

      <div className="ms-checkout-page">

        <NavbarPublica />



        <main className="ms-checkout-main">

          <div className="ms-checkout-empty">

            <p>Cargando tu contratación...</p>

          </div>

        </main>



        <FooterPublico />

        <EstilosCheckout />

      </div>

    );

  }



  // ==========================================================

  // 10. SIN DATOS DE CONTRATACIÓN

  // ==========================================================



  if (!datosRegistro) {

    return (

      <div className="ms-checkout-page">

        <NavbarPublica />



        <main className="ms-checkout-main">

          <div className="ms-checkout-empty">



            <LogoMirrorSoul

              width={120}

              height={85}

              background={false}

            />



            <h1>

              No encontramos tu registro

            </h1>



            <p>

              Regresa a la selección de planes

              y completa tus datos antes de

              continuar al pago.

            </p>



            <button

              type="button"

              className="ms-checkout-primary"

              onClick={() => navigate("/planes")}

            >

              Ver planes

              <span aria-hidden="true">→</span>

            </button>



          </div>

        </main>



        <FooterPublico />

        <EstilosCheckout />

      </div>

    );

  }



  // ==========================================================

  // 11. PANTALLA DE CHECKOUT

  // ==========================================================



  return (

    <div className="ms-checkout-page">



      <NavbarPublica />



      <main className="ms-checkout-main">



        {/* ================================================== */}

        {/* ENCABEZADO */}

        {/* ================================================== */}



        <div className="ms-checkout-heading">



          <span className="ms-checkout-eyebrow">

            CONTRATACIÓN MIRRORSOUL

          </span>



          <h1>

            Finaliza tu contratación

          </h1>



          <p>

            Revisa los datos de tu suscripción

            y continúa de forma segura con

            Mercado Pago.

          </p>



        </div>



        {/* ================================================== */}

        {/* PASOS */}

        {/* ================================================== */}



        <div

          className="ms-checkout-steps"

          aria-label="Progreso de contratación"

        >



          <div className="ms-checkout-step complete">

            <span>✓</span>

            Datos

          </div>



          <div className="ms-checkout-step complete">

            <span>✓</span>

            Resumen

          </div>



          <div

            className="ms-checkout-step active"

            aria-current="step"

          >

            <span>3</span>

            Pago

          </div>



        </div>



        {/* ================================================== */}

        {/* CONTENEDOR DE DOS COLUMNAS */}

        {/* ================================================== */}



        <section className="ms-checkout-grid">



          {/* ================================================= */}

          {/* COLUMNA IZQUIERDA */}

          {/* ================================================= */}



          <div className="ms-checkout-card">



            <span className="ms-checkout-card-label">

              PASO 3 · PAGO

            </span>



            <h2>

              Pago de la suscripción

            </h2>



            <p className="ms-checkout-card-description">

              Tu plan es{" "}

              <strong>{nombrePlan}</strong>.

              Verifica el importe y los datos

              de contratación antes de continuar.

            </p>



            {/* ============================================== */}

            {/* SEGURIDAD */}

            {/* ============================================== */}



            <div className="ms-checkout-security">



              <div

                className="ms-checkout-security-icon"

                aria-hidden="true"

              >

                🔒

              </div>



              <div>

                <strong>Pago seguro</strong>



                <p>

                  MirrorSoul no almacena los datos

                  de tu tarjeta. El pago se

                  procesa directamente mediante

                  Mercado Pago.

                </p>

              </div>



            </div>



            {/* ============================================== */}

            {/* ESTADO DE CONSULTA */}

            {/* ============================================== */}



            {cargandoPrecio && (

              <div

                className="ms-checkout-notice"

                role="status"

              >

                Consultando el importe del plan...

              </div>

            )}



            {/* ============================================== */}

            {/* ERROR */}

            {/* ============================================== */}



            {error && (

              <div

                className="ms-checkout-error"

                role="alert"

              >

                <strong>No podemos continuar todavía</strong>

                <span>{error}</span>

              </div>

            )}



            {/* ============================================== */}

            {/* IMPORTE */}

            {/* ============================================== */}



            <div className="ms-checkout-payment-preview">



              <span>Importe de la suscripción</span>



              <strong>{total}</strong>



              <small>

                {periodo === "anual"

                  ? "Periodo anual"

                  : "Periodo mensual"}

              </small>



            </div>



            {/* ============================================== */}

            {/* BOTÓN MERCADO PAGO */}

            {/* ============================================== */}



            <button

              type="button"

              className="ms-checkout-primary"

              onClick={continuarMercadoPago}

              disabled={!puedePagar}

            >

              {procesandoPago

                ? "Conectando con Mercado Pago..."

                : cargandoPrecio

                  ? "Consultando precio..."

                  : "Continuar con Mercado Pago"}



              {!procesandoPago && (

                <span aria-hidden="true">→</span>

              )}

            </button>



            {/* ============================================== */}

            {/* VOLVER A DATOS */}

            {/* ============================================== */}



            <button

              type="button"

              className="ms-checkout-secondary"

              onClick={regresarARegistro}

              disabled={procesandoPago}

            >

              ← Regresar a mis datos

            </button>



            <p className="ms-checkout-payment-note">

              Al continuar, serás dirigido

              a Mercado Pago para revisar y

              autorizar la suscripción.

            </p>



          </div>



          {/* ================================================= */}

          {/* COLUMNA DERECHA - RESUMEN */}

          {/* ================================================= */}



          <aside className="ms-checkout-summary">



            {/* ============================================== */}

            {/* CABECERA */}

            {/* ============================================== */}



            <div className="ms-checkout-summary-header">



              <div className="ms-checkout-logo">

                <LogoMirrorSoul

                  width={78}

                  height={65}

                  background={false}

                  padding={0}

                />

              </div>



              <div>

                <span className="ms-checkout-card-label">

                  PLAN SELECCIONADO

                </span>



                <h2>{nombrePlan}</h2>

              </div>



            </div>



            <div className="ms-checkout-divider" />



            {/* ============================================== */}

            {/* DATOS DEL PLAN */}

            {/* ============================================== */}



            <FilaResumen

              label="Periodo"

              value={

                periodo === "anual"

                  ? "Anual"

                  : "Mensual"

              }

            />


            {tipoPlan === "independiente" && (

              <FilaResumen

                label="Perfil"

                value={

                  datosRegistro
                    ?.perfil_independiente === "clinica"

                    ? "Psicología / Clínica"

                    : datosRegistro
                        ?.perfil_independiente === "rh"

                      ? "Recursos Humanos"

                      : "Pendiente"

                }

              />

            )}



            <FilaResumen

              label="Licencias"

              value={

                precioPlan?.licencias ?? "—"

              }

            />



            <FilaResumen

              label="Responsable"

              value={

                datosRegistro.nombre_responsable ||

                "—"

              }

            />



            {datosRegistro.nombre_organizacion && (

              <FilaResumen

                label="Organización"

                value={

                  datosRegistro.nombre_organizacion

                }

              />

            )}



            <FilaResumen

              label="Correo"

              value={

                datosRegistro.correo || "—"

              }

            />


            {datosRegistro.telefono && (

              <FilaResumen

                label="Teléfono"

                value={

                  datosRegistro.telefono

                }

              />

            )}



            <FilaResumen

              label="Factura"

              value={

                datosRegistro.requiere_factura

                  ? "Sí"

                  : "No"

              }

            />



            {datosRegistro.requiere_factura &&

              datosRegistro.rfc && (

                <FilaResumen

                  label="RFC"

                  value={datosRegistro.rfc}

                />

              )}



            <div className="ms-checkout-divider" />



            {/* ============================================== */}

            {/* TOTAL */}

            {/* ============================================== */}



            <div className="ms-checkout-total">



              <span>Total</span>



              <strong>{total}</strong>



            </div>



            <p className="ms-checkout-renewal">

              {periodo === "anual"

                ? "Renovación automática anual."

                : "Renovación automática mensual."}

            </p>



            <div className="ms-checkout-summary-footer">

              <span aria-hidden="true">✓</span>



              El importe mostrado se consulta

              directamente desde MirrorSoul.

            </div>



          </aside>



        </section>



      </main>



      <FooterPublico />



      <EstilosCheckout />



    </div>

  );

}



// ============================================================

// 12. ESTILOS DEL CHECKOUT

// ============================================================



function EstilosCheckout() {

  return (

    <style>{`



      /* =====================================================

         MODO CLARO

         ===================================================== */



      :root,

      :root[data-ms-theme="claro"] {

        --chk-bg: linear-gradient(

          180deg,

          #f8fbff 0%,

          #edf5ff 55%,

          #ffffff 100%

        );



        --chk-title: #142842;

        --chk-text: #526782;

        --chk-muted: #62758c;

        --chk-accent: #1768ba;



        --chk-card: #ffffff;

        --chk-border: #d9e6f4;



        --chk-soft: #edf5ff;

        --chk-soft-border: #dbe9f8;



        --chk-success-bg: #e7f8f0;

        --chk-success-text: #176b4c;



        --chk-error-bg: #fff0ef;

        --chk-error-border: #f1c8c4;

        --chk-error-text: #a33332;



        --chk-shadow:

          0 22px 55px rgba(28,63,109,0.09);

      }



      /* =====================================================

         MODO OSCURO

         ===================================================== */



      :root[data-ms-theme="oscuro"] {

        --chk-bg: linear-gradient(

          180deg,

          #07111f 0%,

          #0a1829 55%,

          #07111f 100%

        );



        --chk-title: #ffffff;

        --chk-text: #c3d3e5;

        --chk-muted: #aec1d6;

        --chk-accent: #74e9ff;



        --chk-card: #132338;

        --chk-border: rgba(255,255,255,0.11);



        --chk-soft: #1b3047;

        --chk-soft-border:

          rgba(255,255,255,0.11);



        --chk-success-bg: #173a32;

        --chk-success-text: #90f0c2;



        --chk-error-bg: #38232c;

        --chk-error-border: #78424c;

        --chk-error-text: #ffb9b9;



        --chk-shadow:

          0 25px 70px rgba(0,0,0,0.22);

      }



      /* =====================================================

         PÁGINA

         ===================================================== */



      .ms-checkout-page {

        min-height: 100vh;

        width: 100%;



        background: var(--chk-bg);

        color: var(--chk-title);



        font-family:

          "Inter",

          "Segoe UI",

          Arial,

          sans-serif;



        transition:

          background 0.3s ease,

          color 0.3s ease;

      }



      .ms-checkout-page,

      .ms-checkout-page * {

        box-sizing: border-box;

      }



      .ms-checkout-main {

        max-width: 1200px;



        margin: 0 auto;

        padding: 65px 28px 100px;

      }



      /* =====================================================

         ENCABEZADO

         ===================================================== */



      .ms-checkout-heading {

        max-width: 850px;



        margin: 0 auto 35px;



        text-align: center;

      }



      .ms-checkout-eyebrow,

      .ms-checkout-card-label {

        display: inline-block;



        color: var(--chk-accent);



        font-size: 12px;

        font-weight: 900;



        letter-spacing: 1.5px;

      }



      .ms-checkout-heading h1 {

        margin: 14px 0 0;



        color: var(--chk-title);



        font-size:

          clamp(2.3rem,3.8vw,3.5rem);



        font-weight: 900;

        line-height: 1.1;

        letter-spacing: -1.2px;

      }



      .ms-checkout-heading p {

        margin: 19px auto 0;



        color: var(--chk-text);



        font-size: 17px;

        line-height: 1.75;

      }



      /* =====================================================

         PASOS

         ===================================================== */



      .ms-checkout-steps {

        display: flex;

        justify-content: center;

        align-items: center;



        gap: 15px;



        margin-bottom: 35px;

      }



      .ms-checkout-step {

        display: inline-flex;

        align-items: center;



        gap: 9px;



        padding: 10px 15px;



        border: 1px solid var(--chk-border);

        border-radius: 12px;



        background: var(--chk-card);

        color: var(--chk-muted);



        font-size: 14px;

        font-weight: 800;

      }



      .ms-checkout-step span {

        display: flex;

        align-items: center;

        justify-content: center;



        width: 25px;

        height: 25px;



        border-radius: 8px;



        background: var(--chk-soft);

        color: var(--chk-muted);



        font-size: 13px;

      }



      .ms-checkout-step.complete {

        color: var(--chk-success-text);

      }



      .ms-checkout-step.complete span {

        background: var(--chk-success-bg);

        color: var(--chk-success-text);

      }



      .ms-checkout-step.active {

        border-color: var(--chk-accent);

        color: var(--chk-title);

      }



      .ms-checkout-step.active span {

        background: linear-gradient(

          135deg,

          #65e5ff,

          #917eff

        );



        color: #07111f;

      }



      /* =====================================================

         DOS COLUMNAS

         ===================================================== */



      .ms-checkout-grid {

        display: grid;



        grid-template-columns:

          minmax(0,1fr)

          minmax(300px,380px);



        align-items: start;



        gap: 26px;

      }



      .ms-checkout-card,

      .ms-checkout-summary {

        min-width: 0;



        padding: 35px;



        border-radius: 25px;



        background: var(--chk-card);

        border: 1px solid var(--chk-border);



        box-shadow: var(--chk-shadow);



        color: var(--chk-title);



        transition:

          background 0.3s ease,

          color 0.3s ease,

          border-color 0.3s ease;

      }



      .ms-checkout-summary {

        position: sticky;

        top: 103px;



        padding: 28px;

      }



      /* =====================================================

         TÍTULOS Y TEXTO

         ===================================================== */



      .ms-checkout-card h2 {

        margin: 14px 0;



        color: var(--chk-title);



        font-size:

          clamp(1.9rem,2.5vw,2.5rem);



        font-weight: 900;

        line-height: 1.2;

      }



      .ms-checkout-card-description {

        margin: 0 0 28px;



        color: var(--chk-text);



        font-size: 16px;

        line-height: 1.75;

      }



      .ms-checkout-card-description strong {

        color: var(--chk-title);

      }



      /* =====================================================

         SEGURIDAD

         ===================================================== */



      .ms-checkout-security {

        display: flex;

        align-items: flex-start;



        gap: 16px;



        padding: 23px;

        margin-bottom: 27px;



        border-radius: 18px;



        background: var(--chk-soft);

        border: 1px solid var(--chk-soft-border);

      }



      .ms-checkout-security-icon {

        display: flex;

        align-items: center;

        justify-content: center;



        flex-shrink: 0;



        width: 48px;

        height: 48px;



        border-radius: 13px;



        background: var(--chk-card);



        font-size: 23px;

      }



      .ms-checkout-security strong {

        display: block;



        color: var(--chk-title);



        font-size: 17px;

        font-weight: 900;

      }



      .ms-checkout-security p {

        margin: 9px 0 0;



        color: var(--chk-text);



        font-size: 15px;

        line-height: 1.7;

      }



      /* =====================================================

         AVISOS Y ERRORES

         ===================================================== */



      .ms-checkout-notice {

        padding: 14px 17px;

        margin-bottom: 20px;



        border: 1px solid var(--chk-soft-border);

        border-radius: 12px;



        background: var(--chk-soft);

        color: var(--chk-text);



        font-size: 14px;

      }



      .ms-checkout-error {

        display: flex;

        flex-direction: column;



        gap: 7px;



        padding: 16px;

        margin-bottom: 20px;



        border-radius: 13px;



        background: var(--chk-error-bg);

        border: 1px solid var(--chk-error-border);



        color: var(--chk-error-text);



        line-height: 1.5;

        font-size: 14px;

      }



      .ms-checkout-error strong {

        font-weight: 900;

      }



      /* =====================================================

         IMPORTE

         ===================================================== */



      .ms-checkout-payment-preview {

        display: flex;

        flex-direction: column;



        gap: 10px;



        padding: 23px;

        margin-bottom: 25px;



        border: 1px solid var(--chk-soft-border);

        border-radius: 18px;



        background: var(--chk-soft);

      }



      .ms-checkout-payment-preview > span {

        color: var(--chk-text);



        font-size: 14px;

        font-weight: 800;

      }



      .ms-checkout-payment-preview strong {

        color: var(--chk-title);



        font-size:

          clamp(1.7rem,2.5vw,2.35rem);



        font-weight: 900;

        overflow-wrap: anywhere;

      }



      .ms-checkout-payment-preview small {

        color: var(--chk-muted);



        font-size: 13px;

      }



      /* =====================================================

         BOTONES

         ===================================================== */



      .ms-checkout-primary,

      .ms-checkout-secondary {

        display: flex;

        align-items: center;

        justify-content: center;



        gap: 12px;



        width: 100%;

        min-height: 55px;



        padding: 14px 20px;



        border-radius: 13px;



        font-family: inherit;

        font-size: 15px;

        font-weight: 900;



        cursor: pointer;



        transition:

          transform 0.2s ease,

          opacity 0.2s ease,

          background 0.2s ease;

      }



      .ms-checkout-primary {

        border: none;



        background: linear-gradient(

          135deg,

          #65e5ff,

          #917eff

        );



        color: #07111f;

      }



      .ms-checkout-primary span {

        font-size: 22px;

      }



      .ms-checkout-primary:hover:not(:disabled),

      .ms-checkout-secondary:hover:not(:disabled) {

        transform: translateY(-2px);

      }



      .ms-checkout-primary:disabled,

      .ms-checkout-secondary:disabled {

        opacity: 0.6;

        cursor: not-allowed;

      }



      .ms-checkout-secondary {

        margin-top: 13px;



        background: var(--chk-card);

        border: 1px solid var(--chk-border);



        color: var(--chk-title);

      }



      .ms-checkout-payment-note {

        margin: 19px 0 0;



        color: var(--chk-muted);



        font-size: 13px;

        line-height: 1.65;



        text-align: center;

      }



      /* =====================================================

         RESUMEN

         ===================================================== */



      .ms-checkout-summary-header {

        display: flex;

        align-items: center;



        gap: 13px;

      }



      .ms-checkout-logo {

        display: flex;

        align-items: center;

        justify-content: center;



        flex-shrink: 0;



        background: transparent;

        border: none;

        box-shadow: none;

      }



      .ms-checkout-summary-header h2 {

        margin: 8px 0 0;



        color: var(--chk-title);



        font-size: 25px;

        font-weight: 900;

        line-height: 1.3;

      }



      .ms-checkout-divider {

        height: 1px;



        margin: 24px 0;



        background: var(--chk-border);

      }



      .ms-checkout-summary-row {

        display: flex;

        align-items: flex-start;

        justify-content: space-between;



        gap: 15px;

        margin-bottom: 18px;

      }



      .ms-checkout-summary-row > span {

        color: var(--chk-text);



        font-size: 14px;

        line-height: 1.55;

      }



      .ms-checkout-summary-row > strong {

        color: var(--chk-title);



        font-size: 14px;

        font-weight: 800;

        line-height: 1.55;



        text-align: right;

        overflow-wrap: anywhere;

      }



      /* =====================================================

         TOTAL

         ===================================================== */



      .ms-checkout-total {

        display: flex;

        align-items: center;

        justify-content: space-between;



        gap: 13px;

      }



      .ms-checkout-total > span {

        color: var(--chk-title);



        font-size: 18px;

        font-weight: 900;

      }



      .ms-checkout-total > strong {

        color: var(--chk-accent);



        font-size: 24px;

        font-weight: 900;



        text-align: right;

      }



      .ms-checkout-renewal {

        margin: 16px 0 0;



        color: var(--chk-muted);



        font-size: 13px;

        line-height: 1.6;

      }



      .ms-checkout-summary-footer {

        display: flex;

        align-items: flex-start;



        gap: 10px;



        margin-top: 25px;

        padding: 15px;



        border-radius: 13px;



        background: var(--chk-soft);

        border: 1px solid var(--chk-soft-border);



        color: var(--chk-text);



        font-size: 12px;

        line-height: 1.6;

      }



      .ms-checkout-summary-footer > span {

        color: var(--chk-accent);

        font-weight: 900;

      }



      /* =====================================================

         SIN REGISTRO

         ===================================================== */



      .ms-checkout-empty {

        display: flex;

        align-items: center;

        flex-direction: column;



        gap: 17px;



        max-width: 650px;



        margin: 35px auto;

        padding: 45px 32px;



        background: var(--chk-card);

        border: 1px solid var(--chk-border);

        border-radius: 25px;



        box-shadow: var(--chk-shadow);



        text-align: center;

      }



      .ms-checkout-empty h1 {

        margin: 0;



        color: var(--chk-title);



        font-size:

          clamp(1.9rem,3vw,2.6rem);

      }



      .ms-checkout-empty p {

        margin: 0 0 10px;



        color: var(--chk-text);



        font-size: 16px;

        line-height: 1.75;

      }



      /* =====================================================

         ACCESIBILIDAD

         ===================================================== */



      .ms-checkout-page button:focus-visible {

        outline: 3px solid #2563eb;

        outline-offset: 3px;

      }



      /* =====================================================

         TABLET

         ===================================================== */



      @media (max-width: 950px) {

        .ms-checkout-grid {

          grid-template-columns: 1fr;

        }



        .ms-checkout-summary {

          position: static;

        }



        .ms-checkout-main {

          padding: 55px 22px 80px;

        }

      }



      /* =====================================================

         CELULARES

         ===================================================== */



      @media (max-width: 600px) {

        .ms-checkout-main {

          padding: 45px 16px 65px;

        }



        .ms-checkout-heading {

          margin-bottom: 26px;

        }



        .ms-checkout-heading h1 {

          font-size:

            clamp(2rem,7vw,2.7rem);

        }



        .ms-checkout-heading p {

          font-size: 15px;

        }



        .ms-checkout-steps {

          gap: 6px;

          margin-bottom: 25px;

        }



        .ms-checkout-step {

          flex-direction: column;



          gap: 7px;

          flex: 1;



          padding: 10px 5px;



          font-size: 12px;

        }



        .ms-checkout-card,

        .ms-checkout-summary {

          padding: 24px 19px;

          border-radius: 20px;

        }



        .ms-checkout-security {

          padding: 17px;

          gap: 11px;

        }



        .ms-checkout-security-icon {

          width: 39px;

          height: 39px;

        }



        .ms-checkout-payment-preview {

          padding: 18px;

        }



        .ms-checkout-total strong {

          font-size: 20px;

        }



        .ms-checkout-empty {

          padding: 30px 22px;

        }

      }



      /* =====================================================

         MOVIMIENTO REDUCIDO

         ===================================================== */



      @media (prefers-reduced-motion: reduce) {

        .ms-checkout-page *,

        .ms-checkout-page *::before,

        .ms-checkout-page *::after {

          animation: none !important;

          transition: none !important;

        }

      }



    `}</style>

  );

}



export default CheckoutMirrorSoul;
