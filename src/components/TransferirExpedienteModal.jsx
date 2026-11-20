// src/components/TransferirExpedienteModal.jsx

import React, { useEffect, useState } from "react";
import { getToken } from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;

export default function TransferirExpedienteModal({
  abierto,
  tipo,
  idExpediente,
  nombreExpediente,
  onClose,
  onTransferido
}) {
  const [
    destinos,
    setDestinos
  ] = useState([]);

  const [
    idDestino,
    setIdDestino
  ] = useState("");

  const [
    motivo,
    setMotivo
  ] = useState("");

  const [
    cargando,
    setCargando
  ] = useState(false);

  const [
    guardando,
    setGuardando
  ] = useState(false);

  const [
    error,
    setError
  ] = useState("");

  const esPaciente =
    tipo === "paciente";

  const endpoint =
    esPaciente
      ? "pacientes"
      : "empleados";

  // ==================================================
  // CARGAR DESTINOS AUTORIZADOS
  // ==================================================

  useEffect(() => {
    if (
      !abierto ||
      !idExpediente
    ) {
      return;
    }

    let activo = true;

    const cargarDestinos =
      async () => {
        try {
          setCargando(true);
          setError("");
          setIdDestino("");
          setMotivo("");
          setDestinos([]);

          const token =
            getToken();

          if (!token) {
            throw new Error(
              "Tu sesión no está disponible. Inicia sesión nuevamente."
            );
          }

          const response =
            await fetch(
              `${API_URL}/api/transferencias/${endpoint}/${idExpediente}/destinos`,
              {
                method: "GET",

                headers: {
                  Authorization:
                    `Bearer ${token}`
                }
              }
            );

          const data =
            await response
              .json()
              .catch(
                () => ({})
              );

          if (!response.ok) {
            throw new Error(
              data.message ||
              "No se pudieron obtener los responsables disponibles."
            );
          }

          if (!activo) {
            return;
          }

          setDestinos(
            Array.isArray(
              data.destinos
            )
              ? data.destinos
              : []
          );

        } catch (err) {
          if (!activo) {
            return;
          }

          console.error(
            "❌ Error cargando destinos de transferencia:",
            err
          );

          setError(
            err.message ||
            "No se pudieron obtener los responsables disponibles."
          );

        } finally {
          if (activo) {
            setCargando(false);
          }
        }
      };

    cargarDestinos();

    return () => {
      activo = false;
    };

  }, [
    abierto,
    idExpediente,
    endpoint
  ]);

  // ==================================================
  // CERRAR
  // ==================================================

  const cerrar =
    () => {
      if (
        guardando
      ) {
        return;
      }

      setError("");
      setIdDestino("");
      setMotivo("");
      setDestinos([]);

      onClose?.();
    };

  // ==================================================
  // CONFIRMAR TRANSFERENCIA
  // ==================================================

  const confirmar =
    async event => {
      event.preventDefault();

      if (!idDestino) {
        setError(
          "Selecciona el nuevo responsable."
        );

        return;
      }

      if (
        !motivo.trim()
      ) {
        setError(
          "Selecciona el motivo de la transferencia."
        );

        return;
      }

      try {
        setGuardando(true);
        setError("");

        const token =
          getToken();

        if (!token) {
          throw new Error(
            "Tu sesión no está disponible. Inicia sesión nuevamente."
          );
        }

        const body =
          esPaciente
            ? {
                id_psicologo_destino:
                  Number(
                    idDestino
                  ),

                motivo:
                  motivo.trim()
              }
            : {
                id_usuario_destino:
                  Number(
                    idDestino
                  ),

                motivo:
                  motivo.trim()
              };

        const response =
          await fetch(
            `${API_URL}/api/transferencias/${endpoint}/${idExpediente}`,
            {
              method:
                "POST",

              headers: {
                Authorization:
                  `Bearer ${token}`,

                "Content-Type":
                  "application/json"
              },

              body:
                JSON.stringify(
                  body
                )
            }
          );

        const data =
          await response
            .json()
            .catch(
              () => ({})
            );

        if (!response.ok) {
          throw new Error(
            data.message ||
            "No se pudo realizar la transferencia."
          );
        }

        window.alert(
          data.message ||
          "Transferencia realizada correctamente."
        );

        onTransferido?.(
          data
        );

        cerrar();

      } catch (err) {
        console.error(
          "❌ Error realizando transferencia:",
          err
        );

        setError(
          err.message ||
          "No se pudo realizar la transferencia."
        );

      } finally {
        setGuardando(false);
      }
    };

  // ==================================================
  // NO MOSTRAR SI ESTÁ CERRADO
  // ==================================================

  if (!abierto) {
    return null;
  }

  // ==================================================
  // RENDER
  // ==================================================

  return (
    <div
      style={
        styles.overlay
      }
      onClick={
        cerrar
      }
    >
      <div
        style={
          styles.modal
        }
        onClick={
          event =>
            event.stopPropagation()
        }
      >

        {/* ============================================
            ENCABEZADO
        ============================================ */}

        <div
          style={
            styles.header
          }
        >
          <div>
            <div
              style={
                styles.eyebrow
              }
            >
              TRANSFERENCIA SEGURA
            </div>

            <h2
              style={
                styles.title
              }
            >
              {esPaciente
                ? "🩺 Transferir paciente"
                : "👔 Transferir empleado"}
            </h2>

            <p
              style={
                styles.subtitle
              }
            >
              {nombreExpediente ||
                "Expediente"}
            </p>
          </div>

          <button
            type="button"
            style={
              styles.close
            }
            onClick={
              cerrar
            }
            disabled={
              guardando
            }
          >
            ×
          </button>
        </div>

        {/* ============================================
            AVISO DE SEGURIDAD
        ============================================ */}

        <div
          style={
            styles.notice
          }
        >
          <div
            style={
              styles.noticeTitle
            }
          >
            🔒 Transferencia protegida
          </div>

          <div>
            Solo se muestran responsables autorizados
            de la misma administración y de la misma
            área.
          </div>

          <div
            style={
              styles.noticeSecondary
            }
          >
            El expediente no se duplica. Solamente
            cambia de responsable y conserva toda su
            información e historial.
          </div>
        </div>

        {/* ============================================
            CARGANDO
        ============================================ */}

        {cargando ? (
          <div
            style={
              styles.loading
            }
          >
            <div
              style={
                styles.loadingIcon
              }
            >
              ⏳
            </div>

            <div>
              Cargando colegas disponibles...
            </div>
          </div>
        ) : (
          <form
            onSubmit={
              confirmar
            }
          >

            {/* ========================================
                NUEVO RESPONSABLE
            ======================================== */}

            <label
              style={
                styles.label
              }
            >
              Nuevo responsable
            </label>

            <select
              style={
                styles.input
              }
              value={
                idDestino
              }
              onChange={
                event =>
                  setIdDestino(
                    event.target
                      .value
                  )
              }
              disabled={
                guardando
              }
            >
              <option value="">
                Selecciona un colega
              </option>

              {destinos.map(
                destino => {
                  const id =
                    esPaciente
                      ? destino
                          .id_psicologo
                      : destino
                          .id_usuario;

                  return (
                    <option
                      key={
                        id
                      }
                      value={
                        id
                      }
                    >
                      {destino.nombre}

                      {destino.especialidad
                        ? ` · ${destino.especialidad}`
                        : ""}

                      {destino.puesto
                        ? ` · ${destino.puesto}`
                        : ""}
                    </option>
                  );
                }
              )}
            </select>

            {destinos.length ===
              0 &&
              !error && (
              <div
                style={
                  styles.empty
                }
              >
                No hay otro colega autorizado disponible
                para recibir este expediente.
              </div>
            )}

            {/* ========================================
                MOTIVO
            ======================================== */}

            <label
              style={
                styles.label
              }
            >
              Motivo de la transferencia
            </label>

            <select
              style={
                styles.input
              }
              value={
                motivo
              }
              onChange={
                event =>
                  setMotivo(
                    event.target
                      .value
                  )
              }
              disabled={
                guardando
              }
            >
              <option value="">
                Selecciona un motivo
              </option>

              {esPaciente ? (
                <>
                  <option value="Solicitud del paciente">
                    Solicitud del paciente
                  </option>

                  <option value="Cambio de especialista">
                    Cambio de especialista
                  </option>

                  <option value="Baja del psicólogo">
                    Baja del psicólogo
                  </option>

                  <option value="Ausencia temporal">
                    Ausencia temporal
                  </option>

                  <option value="Reorganización interna">
                    Reorganización interna
                  </option>

                  <option value="Redistribución de pacientes">
                    Redistribución de pacientes
                  </option>

                  <option value="Otro">
                    Otro
                  </option>
                </>
              ) : (
                <>
                  <option value="Cambio de responsable RH">
                    Cambio de responsable RH
                  </option>

                  <option value="Baja del usuario RH">
                    Baja del usuario RH
                  </option>

                  <option value="Ausencia temporal">
                    Ausencia temporal
                  </option>

                  <option value="Reorganización interna">
                    Reorganización interna
                  </option>

                  <option value="Redistribución de carga">
                    Redistribución de carga
                  </option>

                  <option value="Otro">
                    Otro
                  </option>
                </>
              )}
            </select>

            {/* ========================================
                ERROR
            ======================================== */}

            {error && (
              <div
                style={
                  styles.error
                }
              >
                ⚠️ {error}
              </div>
            )}

            {/* ========================================
                RECORDATORIO
            ======================================== */}

            <div
              style={
                styles.warning
              }
            >
              <strong>
                Importante:
              </strong>{" "}
              después de confirmar la transferencia,
              el responsable anterior dejará de tener
              acceso al expediente, salvo que también
              tenga permisos administrativos.
            </div>

            {/* ========================================
                BOTONES
            ======================================== */}

            <div
              style={
                styles.actions
              }
            >
              <button
                type="button"
                style={
                  styles.cancel
                }
                onClick={
                  cerrar
                }
                disabled={
                  guardando
                }
              >
                Cancelar
              </button>

              <button
                type="submit"
                style={{
                  ...styles.primary,

                  opacity:
                    guardando ||
                    destinos.length ===
                      0
                      ? 0.6
                      : 1
                }}
                disabled={
                  guardando ||
                  destinos.length ===
                    0
                }
              >
                {guardando
                  ? "Transfiriendo..."
                  : "Confirmar transferencia"}
              </button>
            </div>

          </form>
        )}

      </div>
    </div>
  );
}

// ==================================================
// ESTILOS
// ==================================================

const styles = {
  overlay: {
    position:
      "fixed",

    inset:
      0,

    background:
      "rgba(15,23,42,.55)",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    padding:
      20,

    zIndex:
      9999,

    backdropFilter:
      "blur(3px)"
  },

  modal: {
    width:
      "100%",

    maxWidth:
      600,

    maxHeight:
      "90vh",

    overflowY:
      "auto",

    background:
      "#ffffff",

    borderRadius:
      18,

    padding:
      24,

    boxShadow:
      "0 24px 70px rgba(15,23,42,.24)",

    boxSizing:
      "border-box"
  },

  header: {
    display:
      "flex",

    justifyContent:
      "space-between",

    gap:
      18,

    alignItems:
      "flex-start"
  },

  eyebrow: {
    fontSize:
      11,

    fontWeight:
      800,

    letterSpacing:
      1.1,

    color:
      "#64748B"
  },

  title: {
    margin:
      "5px 0 2px",

    color:
      "#172B4D",

    fontSize:
      23
  },

  subtitle: {
    margin:
      0,

    color:
      "#64748B",

    fontSize:
      14
  },

  close: {
    border:
      "none",

    background:
      "#F1F5F9",

    color:
      "#64748B",

    width:
      34,

    height:
      34,

    borderRadius:
      "50%",

    cursor:
      "pointer",

    fontSize:
      22,

    flexShrink:
      0
  },

  notice: {
    margin:
      "18px 0",

    padding:
      14,

    background:
      "#EEF4FF",

    border:
      "1px solid #C9DAFA",

    borderRadius:
      10,

    color:
      "#35527C",

    fontSize:
      13,

    lineHeight:
      1.5
  },

  noticeTitle: {
    color:
      "#2167D5",

    fontWeight:
      800,

    marginBottom:
      5
  },

  noticeSecondary: {
    marginTop:
      6,

    color:
      "#64748B",

    fontSize:
      12
  },

  label: {
    display:
      "block",

    margin:
      "14px 0 6px",

    color:
      "#344054",

    fontWeight:
      700,

    fontSize:
      13
  },

  input: {
    width:
      "100%",

    minHeight:
      44,

    border:
      "1px solid #D0D5DD",

    borderRadius:
      9,

    padding:
      "9px 11px",

    background:
      "#ffffff",

    color:
      "#344054",

    boxSizing:
      "border-box",

    outline:
      "none"
  },

  empty: {
    marginTop:
      8,

    padding:
      "10px 12px",

    borderRadius:
      9,

    background:
      "#F8FAFC",

    border:
      "1px solid #E2E8F0",

    color:
      "#667085",

    fontSize:
      12,

    lineHeight:
      1.5
  },

  loading: {
    padding:
      "32px 0",

    color:
      "#667085",

    textAlign:
      "center"
  },

  loadingIcon: {
    fontSize:
      28,

    marginBottom:
      8
  },

  error: {
    marginTop:
      14,

    padding:
      11,

    borderRadius:
      8,

    background:
      "#FEF3F2",

    border:
      "1px solid #FECDCA",

    color:
      "#B42318",

    fontSize:
      13,

    lineHeight:
      1.5
  },

  warning: {
    marginTop:
      16,

    padding:
      "11px 12px",

    background:
      "#FFF9E8",

    border:
      "1px solid #F4DFA0",

    borderRadius:
      9,

    color:
      "#6B5A16",

    fontSize:
      12,

    lineHeight:
      1.5
  },

  actions: {
    display:
      "flex",

    justifyContent:
      "flex-end",

    gap:
      10,

    marginTop:
      22,

    flexWrap:
      "wrap"
  },

  cancel: {
    border:
      "1px solid #D0D5DD",

    background:
      "#ffffff",

    color:
      "#344054",

    padding:
      "10px 15px",

    borderRadius:
      9,

    cursor:
      "pointer",

    fontWeight:
      700
  },

  primary: {
    border:
      "none",

    background:
      "#2867D7",

    color:
      "#ffffff",

    padding:
      "10px 15px",

    borderRadius:
      9,

    cursor:
      "pointer",

    fontWeight:
      800
  }
};