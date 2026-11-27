// ============================================================
// src/views/public/PagoExitoso.jsx
// ============================================================

import React, {
  useEffect,
  useState,
} from "react";

import {
  useNavigate,
  useSearchParams,
} from "react-router-dom";


// ============================================================
// API
// ============================================================

const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://www.reflejoyalma.com";


// ============================================================
// COMPONENTE
// ============================================================

export default function PagoExitoso() {

  const navigate =
    useNavigate();


  const [
    searchParams
  ] =
    useSearchParams();


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
    estado,
    setEstado
  ] =
    useState(
      "consultando"
    );


  const [
    mensaje,
    setMensaje
  ] =
    useState(
      "Estamos verificando tu pago..."
    );


  const [
    detalle,
    setDetalle
  ] =
    useState(
      null
    );


  const [
    error,
    setError
  ] =
    useState(
      ""
    );


  // ==========================================================
  // OBTENER PREAPPROVAL ID
  // ==========================================================

  const obtenerPreapprovalId =
    () => {

      // --------------------------------------------
      // 1. Mercado Pago puede regresarlo en la URL
      // --------------------------------------------

      const desdeURL =
        searchParams.get(
          "preapproval_id"
        );


      if (
        desdeURL
      ) {
        return desdeURL;
      }


      // --------------------------------------------
      // 2. Buscarlo en sessionStorage
      // --------------------------------------------

      try {

        const guardado =
          sessionStorage.getItem(
            "mirrorsoul_pago_actual"
          );


        if (
          guardado
        ) {

          const datos =
            JSON.parse(
              guardado
            );


          return (
            datos
              ?.mercado_pago
              ?.id ||

            datos
              ?.id ||

            datos
              ?.preapproval_id ||

            null
          );

        }

      } catch (
        storageError
      ) {

        console.error(
          "Error leyendo pago guardado:",
          storageError
        );

      }


      return null;
    };


  // ==========================================================
  // VERIFICAR PAGO
  // ==========================================================

  useEffect(
    () => {

      let activo =
        true;


      const verificarPago =
        async () => {

          try {

            setCargando(
              true
            );

            setError(
              ""
            );


            const preapprovalId =
              obtenerPreapprovalId();


            if (
              !preapprovalId
            ) {

              if (
                !activo
              ) {
                return;
              }


              setEstado(
                "sin_referencia"
              );


              setMensaje(
                "No encontramos la referencia de tu suscripción."
              );


              setError(
                "No se recibió el identificador de la suscripción de Mercado Pago."
              );


              return;
            }


            // =================================================
            // CONSULTAR BACKEND
            //
            // Este endpoint también activa MirrorSoul si
            // Mercado Pago devuelve status = authorized.
            // =================================================

            const response =
              await fetch(
                `${API_URL}/api/pagos/suscripcion/${encodeURIComponent(
                  preapprovalId
                )}`,
                {
                  method:
                    "GET",

                  headers: {
                    Accept:
                      "application/json",
                  },
                }
              );


            const data =
              await response.json();


            if (
              !response.ok
            ) {

              throw new Error(
                data?.message ||
                data?.error ||
                "No fue posible verificar la suscripción."
              );

            }


            if (
              !activo
            ) {
              return;
            }


            const suscripcion =
              data?.suscripcion ||
              data;


            const status =
              String(
                suscripcion
                  ?.status ||
                ""
              )
                .trim()
                .toLowerCase();


            const activacion =
              suscripcion
                ?.activacion_mirrorsoul ||
              null;


            // =================================================
            // PAGO AUTORIZADO
            // =================================================

            if (
              status ===
              "authorized"
            ) {

              setEstado(
                "authorized"
              );


              setMensaje(
                "¡Pago aprobado y cuenta activada!"
              );


              setDetalle({
                preapprovalId:

                  suscripcion
                    ?.id ||
                  preapprovalId,

                plan:

                  suscripcion
                    ?.reason ||
                  "MirrorSoul",

                monto:

                  suscripcion
                    ?.auto_recurring
                    ?.transaction_amount ||
                  null,

                moneda:

                  suscripcion
                    ?.auto_recurring
                    ?.currency_id ||
                  "MXN",

                proximoPago:

                  suscripcion
                    ?.next_payment_date ||
                  null,

                organizacion:

                  activacion
                    ?.id_organizacion ||
                  null,

                suscripcionInterna:

                  activacion
                    ?.id_suscripcion ||
                  null,

                usuarioAdmin:

                  activacion
                    ?.id_usuario_admin ||
                  null,

                yaActivada:

                  activacion
                    ?.ya_activada ??
                  null,

                correoAdmin:

                  activacion
                    ?.correo_admin ||
                  null,

                requiereConfigurarPassword:

                  Boolean(
                    activacion
                      ?.requiere_configurar_password
                  ),

                tokenGenerado:

                  Boolean(
                    activacion
                      ?.token_generado
                  ),

                correoEnviado:

                  Boolean(
                    activacion
                      ?.correo_enviado
                  ),

                correoAceptadoSmtp:

                  Boolean(
                    activacion
                      ?.correo_aceptado_smtp
                  ),

                errorCorreo:

                  activacion
                    ?.error_correo ||
                  null,
              });


              // -----------------------------------------------
              // Ya no necesitamos conservar el registro
              // temporal del checkout.
              // -----------------------------------------------

              try {

                sessionStorage.removeItem(
                  "mirrorsoul_plan_registro"
                );

              } catch (
                storageError
              ) {

                console.error(
                  storageError
                );

              }


              return;
            }


            // =================================================
            // PENDIENTE
            // =================================================

            if (
              status ===
              "pending"
            ) {

              setEstado(
                "pending"
              );


              setMensaje(
                "Tu suscripción todavía está pendiente."
              );


              setDetalle({
                preapprovalId:
                  suscripcion
                    ?.id ||
                  preapprovalId,

                plan:
                  suscripcion
                    ?.reason ||
                  "MirrorSoul",
              });


              return;
            }


            // =================================================
            // CANCELADA
            // =================================================

            if (
              status ===
              "cancelled" ||
              status ===
              "canceled"
            ) {

              setEstado(
                "cancelled"
              );


              setMensaje(
                "La suscripción fue cancelada."
              );


              return;
            }


            // =================================================
            // PAUSADA
            // =================================================

            if (
              status ===
              "paused"
            ) {

              setEstado(
                "paused"
              );


              setMensaje(
                "La suscripción se encuentra pausada."
              );


              return;
            }


            // =================================================
            // OTRO ESTADO
            // =================================================

            setEstado(
              status ||
              "desconocido"
            );


            setMensaje(
              "Recibimos tu información de pago, pero todavía estamos confirmando su estado."
            );


            setDetalle(
              suscripcion
            );


          } catch (
            err
          ) {

            console.error(
              "Error verificando pago:",
              err
            );


            if (
              activo
            ) {

              setEstado(
                "error"
              );


              setMensaje(
                "No pudimos verificar tu pago."
              );


              setError(
                err.message ||
                "Ocurrió un error inesperado."
              );

            }

          } finally {

            if (
              activo
            ) {

              setCargando(
                false
              );

            }

          }

        };


      verificarPago();


      return () => {

        activo =
          false;

      };

    },
    [
      searchParams
    ]
  );


  // ==========================================================
  // FORMATEAR FECHA
  // ==========================================================

  const formatearFecha =
    (
      fecha
    ) => {

      if (
        !fecha
      ) {
        return "";
      }


      try {

        return new Intl.DateTimeFormat(
          "es-MX",
          {
            day:
              "2-digit",

            month:
              "long",

            year:
              "numeric",
          }
        ).format(
          new Date(
            fecha
          )
        );

      } catch {

        return fecha;

      }

    };


  // ==========================================================
  // FORMATEAR MONTO
  // ==========================================================

  const formatearMonto =
    (
      monto,
      moneda
    ) => {

      if (
        monto ===
        null ||
        monto ===
        undefined
      ) {
        return "";
      }


      try {

        return new Intl.NumberFormat(
          "es-MX",
          {
            style:
              "currency",

            currency:
              moneda ||
              "MXN",
          }
        ).format(
          Number(
            monto
          )
        );

      } catch {

        return `$${monto}`;

      }

    };


  // ==========================================================
  // CONTINUAR AL ACCESO
  //
  // Si el administrador todavía debe crear su contraseña,
  // no lo mandamos al login porque aún no puede entrar.
  // El enlace seguro se envía por correo desde el backend.
  // ==========================================================

  const continuarAlAcceso =
    () => {

      if (
        detalle
          ?.requiereConfigurarPassword
      ) {

        return;
      }


      navigate(
        "/login"
      );

    };


  // ==========================================================
  // VOLVER A PLANES
  // ==========================================================

  const volverAPlanes =
    () => {

      navigate(
        "/planes"
      );

    };


  // ==========================================================
  // REINTENTAR
  // ==========================================================

  const reintentar =
    () => {

      window.location.reload();

    };


  // ==========================================================
  // ESTILOS
  // ==========================================================

  const estilos = {

    pagina: {
      minHeight:
        "100vh",

      display:
        "flex",

      alignItems:
        "center",

      justifyContent:
        "center",

      padding:
        "40px 20px",

      background:
        "linear-gradient(135deg, #07111f 0%, #101c35 48%, #13243f 100%)",

      fontFamily:
        "Inter, system-ui, Arial, sans-serif",
    },


    tarjeta: {
      width:
        "100%",

      maxWidth:
        "720px",

      background:
        "rgba(255,255,255,0.97)",

      borderRadius:
        "28px",

      padding:
        "42px",

      boxShadow:
        "0 25px 80px rgba(0,0,0,.28)",

      textAlign:
        "center",
    },


    icono: {
      width:
        "86px",

      height:
        "86px",

      borderRadius:
        "50%",

      margin:
        "0 auto 20px",

      display:
        "flex",

      alignItems:
        "center",

      justifyContent:
        "center",

      fontSize:
        "42px",

      background:
        estado ===
        "authorized"
          ? "#e8f8ef"
          : estado ===
            "error"
            ? "#fdecec"
            : "#eef4ff",
    },


    titulo: {
      margin:
        "0 0 12px",

      fontSize:
        "34px",

      fontWeight:
        "800",

      color:
        "#10233f",
    },


    mensaje: {
      fontSize:
        "18px",

      lineHeight:
        "1.6",

      color:
        "#526176",

      marginBottom:
        "28px",
    },


    detalle: {
      background:
        "#f6f8fc",

      border:
        "1px solid #e4e9f2",

      borderRadius:
        "18px",

      padding:
        "22px",

      textAlign:
        "left",

      margin:
        "24px 0",
    },


    fila: {
      display:
        "flex",

      justifyContent:
        "space-between",

      gap:
        "20px",

      padding:
        "11px 0",

      borderBottom:
        "1px solid #e8edf5",
    },


    etiqueta: {
      color:
        "#69788e",

      fontWeight:
        "600",
    },


    valor: {
      color:
        "#172b48",

      fontWeight:
        "700",

      textAlign:
        "right",

      wordBreak:
        "break-word",
    },


    alerta: {
      padding:
        "16px 18px",

      borderRadius:
        "14px",

      background:
        "#fff3f3",

      color:
        "#b42318",

      margin:
        "20px 0",

      lineHeight:
        "1.5",
    },


    acciones: {
      display:
        "flex",

      gap:
        "12px",

      justifyContent:
        "center",

      flexWrap:
        "wrap",

      marginTop:
        "28px",
    },


    botonPrincipal: {
      border:
        "none",

      borderRadius:
        "14px",

      padding:
        "14px 24px",

      background:
        "#162b4d",

      color:
        "#ffffff",

      cursor:
        "pointer",

      fontSize:
        "16px",

      fontWeight:
        "700",
    },


    botonSecundario: {
      border:
        "1px solid #cfd7e4",

      borderRadius:
        "14px",

      padding:
        "14px 24px",

      background:
        "#ffffff",

      color:
        "#253b5c",

      cursor:
        "pointer",

      fontSize:
        "16px",

      fontWeight:
        "700",
    },


    cargando: {
      width:
        "42px",

      height:
        "42px",

      margin:
        "0 auto 22px",

      border:
        "4px solid #dfe7f2",

      borderTop:
        "4px solid #19375f",

      borderRadius:
        "50%",

      animation:
        "mirrorsoulSpin 0.8s linear infinite",
    },

  };


  // ==========================================================
  // ICONO SEGÚN ESTADO
  // ==========================================================

  const obtenerIcono =
    () => {

      if (
        estado ===
        "authorized"
      ) {
        return "✓";
      }


      if (
        estado ===
        "error" ||
        estado ===
        "cancelled"
      ) {
        return "!";
      }


      return "⏳";
    };


  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <div
      style={
        estilos.pagina
      }
    >

      <style>
        {`
          @keyframes mirrorsoulSpin {
            from {
              transform: rotate(0deg);
            }

            to {
              transform: rotate(360deg);
            }
          }

          @media (max-width: 600px) {
            .mirrorsoul-pago-card {
              padding: 28px 20px !important;
            }
          }
        `}
      </style>


      <div
        className="mirrorsoul-pago-card"
        style={
          estilos.tarjeta
        }
      >

        {/* ==================================================
            CARGANDO
        ================================================== */}

        {cargando ? (
          <>
            <div
              style={
                estilos.cargando
              }
            />

            <h1
              style={
                estilos.titulo
              }
            >
              Verificando pago
            </h1>

            <p
              style={
                estilos.mensaje
              }
            >
              Estamos confirmando tu suscripción
              con Mercado Pago y activando tu cuenta
              de MirrorSoul.
            </p>
          </>
        ) : (
          <>

            {/* ==================================================
                ICONO
            ================================================== */}

            <div
              style={
                estilos.icono
              }
            >
              {obtenerIcono()}
            </div>


            {/* ==================================================
                TÍTULO
            ================================================== */}

            <h1
              style={
                estilos.titulo
              }
            >
              {mensaje}
            </h1>


            {/* ==================================================
                AUTORIZADO
            ================================================== */}

            {estado ===
              "authorized" && (
              <>

                <p
                  style={
                    estilos.mensaje
                  }
                >
                  Tu suscripción de MirrorSoul está activa.
                  Tu organización y tu cuenta de administrador
                  ya fueron creadas correctamente.
                </p>


                {detalle && (
                  <div
                    style={
                      estilos.detalle
                    }
                  >

                    {detalle.plan && (
                      <div
                        style={
                          estilos.fila
                        }
                      >
                        <span
                          style={
                            estilos.etiqueta
                          }
                        >
                          Plan
                        </span>

                        <span
                          style={
                            estilos.valor
                          }
                        >
                          {detalle.plan}
                        </span>
                      </div>
                    )}


                    {detalle.monto && (
                      <div
                        style={
                          estilos.fila
                        }
                      >
                        <span
                          style={
                            estilos.etiqueta
                          }
                        >
                          Pago
                        </span>

                        <span
                          style={
                            estilos.valor
                          }
                        >
                          {formatearMonto(
                            detalle.monto,
                            detalle.moneda
                          )}
                        </span>
                      </div>
                    )}


                    {detalle.proximoPago && (
                      <div
                        style={
                          estilos.fila
                        }
                      >
                        <span
                          style={
                            estilos.etiqueta
                          }
                        >
                          Próxima renovación
                        </span>

                        <span
                          style={
                            estilos.valor
                          }
                        >
                          {formatearFecha(
                            detalle.proximoPago
                          )}
                        </span>
                      </div>
                    )}


                    {detalle.organizacion && (
                      <div
                        style={
                          estilos.fila
                        }
                      >
                        <span
                          style={
                            estilos.etiqueta
                          }
                        >
                          Organización
                        </span>

                        <span
                          style={
                            estilos.valor
                          }
                        >
                          #{detalle.organizacion}
                        </span>
                      </div>
                    )}

                  </div>
                )}


                <p
                  style={{
                    ...estilos.mensaje,
                    fontSize:
                      "15px",
                  }}
                >
                  {detalle
                    ?.requiereConfigurarPassword
                    ? (
                        <>
                          Te enviamos un enlace seguro
                          para crear la contraseña de
                          acceso de tu administrador
                          {detalle?.correoAdmin
                            ? (
                                <>
                                  {" "}a{" "}
                                  <strong>
                                    {detalle.correoAdmin}
                                  </strong>
                                </>
                              )
                            : null}
                          .
                        </>
                      )
                    : (
                        <>
                          Tu acceso ya está configurado.
                          Puedes iniciar sesión.
                        </>
                      )}
                </p>


                {detalle
                  ?.requiereConfigurarPassword &&
                  detalle?.errorCorreo && (
                  <div
                    style={
                      estilos.alerta
                    }
                  >
                    No pudimos confirmar el envío del
                    correo de acceso.
                    <br />
                    <strong>
                      Detalle:
                    </strong>{" "}
                    {detalle.errorCorreo}
                  </div>
                )}


                <div
                  style={
                    estilos.acciones
                  }
                >

                  <button
                    type="button"
                    style={{
                      ...estilos.botonPrincipal,
                      opacity:
                        detalle
                          ?.requiereConfigurarPassword
                          ? 0.78
                          : 1,
                      cursor:
                        detalle
                          ?.requiereConfigurarPassword
                          ? "default"
                          : "pointer",
                    }}
                    onClick={
                      continuarAlAcceso
                    }
                  >
                    {detalle
                      ?.requiereConfigurarPassword
                      ? "Revisa tu correo para crear tu contraseña"
                      : "Iniciar sesión"}
                  </button>

                </div>

              </>
            )}


            {/* ==================================================
                PENDIENTE
            ================================================== */}

            {estado ===
              "pending" && (
              <>

                <p
                  style={
                    estilos.mensaje
                  }
                >
                  Mercado Pago todavía está procesando
                  la suscripción. Puedes volver a verificar
                  el estado sin realizar otro pago.
                </p>


                <div
                  style={
                    estilos.acciones
                  }
                >

                  <button
                    type="button"
                    style={
                      estilos.botonPrincipal
                    }
                    onClick={
                      reintentar
                    }
                  >
                    Verificar nuevamente
                  </button>


                  <button
                    type="button"
                    style={
                      estilos.botonSecundario
                    }
                    onClick={
                      volverAPlanes
                    }
                  >
                    Volver a planes
                  </button>

                </div>

              </>
            )}


            {/* ==================================================
                ERROR
            ================================================== */}

            {estado ===
              "error" && (
              <>

                <p
                  style={
                    estilos.mensaje
                  }
                >
                  El pago no necesariamente se perdió.
                  Simplemente no pudimos confirmar su
                  estado en este momento.
                </p>


                {error && (
                  <div
                    style={
                      estilos.alerta
                    }
                  >
                    {error}
                  </div>
                )}


                <div
                  style={
                    estilos.acciones
                  }
                >

                  <button
                    type="button"
                    style={
                      estilos.botonPrincipal
                    }
                    onClick={
                      reintentar
                    }
                  >
                    Intentar nuevamente
                  </button>


                  <button
                    type="button"
                    style={
                      estilos.botonSecundario
                    }
                    onClick={
                      volverAPlanes
                    }
                  >
                    Volver a planes
                  </button>

                </div>

              </>
            )}


            {/* ==================================================
                SIN REFERENCIA
            ================================================== */}

            {estado ===
              "sin_referencia" && (
              <>

                {error && (
                  <div
                    style={
                      estilos.alerta
                    }
                  >
                    {error}
                  </div>
                )}


                <div
                  style={
                    estilos.acciones
                  }
                >

                  <button
                    type="button"
                    style={
                      estilos.botonSecundario
                    }
                    onClick={
                      volverAPlanes
                    }
                  >
                    Regresar a planes
                  </button>

                </div>

              </>
            )}


            {/* ==================================================
                CANCELADA / PAUSADA / OTROS
            ================================================== */}

            {[
              "cancelled",
              "canceled",
              "paused",
              "desconocido",
            ].includes(
              estado
            ) && (
              <>

                <p
                  style={
                    estilos.mensaje
                  }
                >
                  La cuenta todavía no puede activarse
                  porque la suscripción no se encuentra
                  autorizada.
                </p>


                <div
                  style={
                    estilos.acciones
                  }
                >

                  <button
                    type="button"
                    style={
                      estilos.botonSecundario
                    }
                    onClick={
                      volverAPlanes
                    }
                  >
                    Volver a planes
                  </button>

                </div>

              </>
            )}

          </>
        )}

      </div>

    </div>
  );
}