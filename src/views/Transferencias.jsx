// src/views/Transferencias.jsx

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  getCurrentUser,
  getToken
} from "../services/AuthService";

import TransferirExpedienteModal from "../components/TransferirExpedienteModal";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;

export default function Transferencias() {
  const navigate = useNavigate();
  const user = getCurrentUser();

  const [
    loading,
    setLoading
  ] = useState(true);

  const [
    error,
    setError
  ] = useState("");

  const [
    pacientes,
    setPacientes
  ] = useState([]);

  const [
    empleados,
    setEmpleados
  ] = useState([]);

  const [
    seleccionado,
    setSeleccionado
  ] = useState(null);

  const [
    mostrarModal,
    setMostrarModal
  ] = useState(false);

  // ==================================================
  // USUARIO
  // ==================================================

  const tipoAdmin =
    user?.tipo_admin
      ? String(
          user.tipo_admin
        )
          .trim()
          .toLowerCase()
      : null;

  const area =
    user?.area
      ? String(
          user.area
        )
          .trim()
          .toLowerCase()
      : null;

  const rol =
    user?.rol
      ? String(
          user.rol
        )
          .trim()
          .toLowerCase()
      : null;

  const esMaster =
    user?.role === 1 &&
    tipoAdmin === "master";

  const esAdminClinica =
    user?.role === 1 &&
    tipoAdmin === "normal" &&
    area === "clinica";

  const esAdminRH =
    user?.role === 1 &&
    tipoAdmin === "normal" &&
    area === "rh";

  const esPsicologo =
    user?.role === 2 &&
    rol === "psicologo";

  const esUsuarioRH =
    user?.role === 2 &&
    rol === "rh";

  const puedeClinica =
    esMaster ||
    esAdminClinica ||
    esPsicologo;

  const puedeRH =
    esMaster ||
    esAdminRH ||
    esUsuarioRH;

  // ==================================================
  // CARGAR DATOS
  // ==================================================

  useEffect(() => {
    const cargar =
      async () => {
        try {
          setLoading(true);
          setError("");

          const token =
            getToken();

          if (!token) {
            navigate(
              "/login",
              {
                replace: true
              }
            );

            return;
          }

          const tareas = [];

          // ============================================
          // CLÍNICA
          // ============================================

          if (
            puedeClinica
          ) {
            tareas.push(
              fetch(
                `${API_URL}/api/pacientes`,
                {
                  headers: {
                    Authorization:
                      `Bearer ${token}`
                  }
                }
              )
                .then(
                  async res => {
                    if (
                      !res.ok
                    ) {
                      return [];
                    }

                    const data =
                      await res.json();

                    return Array.isArray(
                      data
                    )
                      ? data
                      : Array.isArray(
                          data?.pacientes
                        )
                      ? data.pacientes
                      : [];
                  }
                )
                .then(
                  lista =>
                    setPacientes(
                      lista
                    )
                )
            );
          }

          // ============================================
          // RH
          // ============================================

          if (
            puedeRH
          ) {
            tareas.push(
              fetch(
                `${API_URL}/api/empleados`,
                {
                  headers: {
                    Authorization:
                      `Bearer ${token}`
                  }
                }
              )
                .then(
                  async res => {
                    if (
                      !res.ok
                    ) {
                      return [];
                    }

                    const data =
                      await res.json();

                    return Array.isArray(
                      data
                    )
                      ? data
                      : Array.isArray(
                          data?.empleados
                        )
                      ? data.empleados
                      : Array.isArray(
                          data?.data
                        )
                      ? data.data
                      : [];
                  }
                )
                .then(
                  lista =>
                    setEmpleados(
                      lista
                    )
                )
            );
          }

          await Promise.all(
            tareas
          );

        } catch (
          err
        ) {
          console.error(
            "❌ Error cargando transferencias:",
            err
          );

          setError(
            "No fue posible cargar la información."
          );

        } finally {
          setLoading(false);
        }
      };

    cargar();

  }, [
    navigate,
    puedeClinica,
    puedeRH
  ]);

  // ==================================================
  // ABRIR MODAL
  // ==================================================

  const abrirTransferencia =
    (
      tipo,
      item
    ) => {
      setSeleccionado({
        tipo,
        item
      });

      setMostrarModal(
        true
      );
    };

  // ==================================================
  // TRANSFERENCIA COMPLETADA
  // ==================================================

  const transferenciaRealizada =
    () => {
      setMostrarModal(
        false
      );

      setSeleccionado(
        null
      );

      window.location.reload();
    };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (
    loading
  ) {
    return (
      <div
        style={
          loadingContainer
        }
      >
        <div
          style={
            loadingIcon
          }
        >
          ⏳
        </div>

        <h2>
          Cargando transferencias...
        </h2>

        <p>
          Estamos consultando los expedientes disponibles.
        </p>
      </div>
    );
  }

  // ==================================================
  // RENDER
  // ==================================================

  return (
    <div
      style={
        page
      }
    >
      {/* ==============================================
          ENCABEZADO
      ============================================== */}

      <div
        style={
          header
        }
      >
        <button
          type="button"
          style={
            backButton
          }
          onClick={() =>
            navigate(
              "/dashboard"
            )
          }
        >
          ⬅ Volver
        </button>

        <div>
          <div
            style={
              label
            }
          >
            MIRRORSOUL
          </div>

          <h1
            style={
              title
            }
          >
            🔁 Transferencias
          </h1>

          <p
            style={
              subtitle
            }
          >
            Gestiona reasignaciones de expedientes entre responsables autorizados.
          </p>
        </div>
      </div>

      {/* ==============================================
          AVISO
      ============================================== */}

      <div
        style={
          notice
        }
      >
        🔒 Las transferencias solo pueden realizarse dentro de la misma organización y área.
        Clínica y RH permanecen completamente separados.
      </div>

      {error && (
        <div
          style={
            errorBox
          }
        >
          ⚠️ {error}
        </div>
      )}

      {/* ==============================================
          CLÍNICA
      ============================================== */}

      {puedeClinica && (
        <section
          style={
            section
          }
        >
          <div
            style={
              sectionHeader
            }
          >
            <div
              style={
                sectionIcon
              }
            >
              🧠
            </div>

            <div>
              <h2
                style={
                  sectionTitle
                }
              >
                Clínica
              </h2>

              <p
                style={
                  sectionDescription
                }
              >
                Pacientes disponibles para reasignación clínica.
              </p>
            </div>
          </div>

          {pacientes.length ===
          0 ? (
            <div
              style={
                emptyBox
              }
            >
              No hay pacientes disponibles para transferir.
            </div>
          ) : (
            <div
              style={
                list
              }
            >
              {pacientes.map(
                paciente => (
                  <div
                    key={
                      paciente.id_paciente
                    }
                    style={
                      itemCard
                    }
                  >
                    <div
                      style={
                        avatar
                      }
                    >
                      {paciente.nombre
                        ?.charAt(
                          0
                        )
                        ?.toUpperCase() ||
                        "P"}
                    </div>

                    <div
                      style={
                        itemInfo
                      }
                    >
                      <h3
                        style={
                          itemName
                        }
                      >
                        {
                          paciente.nombre
                        }
                      </h3>

                      <div
                        style={
                          itemMeta
                        }
                      >
                        🆔{" "}
                        {
                          paciente.id_mirror ||
                          "Sin ID"
                        }
                      </div>
                    </div>

                    <button
                      type="button"
                      style={
                        transferButton
                      }
                      onClick={() =>
                        abrirTransferencia(
                          "paciente",
                          paciente
                        )
                      }
                    >
                      🔁 Transferir
                    </button>
                  </div>
                )
              )}
            </div>
          )}
        </section>
      )}

      {/* ==============================================
          RH
      ============================================== */}

      {puedeRH && (
        <section
          style={
            section
          }
        >
          <div
            style={
              sectionHeader
            }
          >
            <div
              style={
                sectionIcon
              }
            >
              👔
            </div>

            <div>
              <h2
                style={
                  sectionTitle
                }
              >
                Recursos Humanos
              </h2>

              <p
                style={
                  sectionDescription
                }
              >
                Empleados disponibles para reasignación de responsable RH.
              </p>
            </div>
          </div>

          {empleados.length ===
          0 ? (
            <div
              style={
                emptyBox
              }
            >
              No hay empleados disponibles para transferir.
            </div>
          ) : (
            <div
              style={
                list
              }
            >
              {empleados.map(
                empleado => (
                  <div
                    key={
                      empleado.id_empleado
                    }
                    style={
                      itemCard
                    }
                  >
                    <div
                      style={
                        avatarRH
                      }
                    >
                      {empleado.nombre
                        ?.charAt(
                          0
                        )
                        ?.toUpperCase() ||
                        "E"}
                    </div>

                    <div
                      style={
                        itemInfo
                      }
                    >
                      <h3
                        style={
                          itemName
                        }
                      >
                        {
                          empleado.nombre
                        }
                      </h3>

                      <div
                        style={
                          itemMeta
                        }
                      >
                        🆔{" "}
                        {
                          empleado.id_mirror ||
                          "Sin ID"
                        }
                      </div>

                      {empleado.puesto && (
                        <div
                          style={
                            itemSubMeta
                          }
                        >
                          👔 {
                            empleado.puesto
                          }
                        </div>
                      )}
                    </div>

                    <button
                      type="button"
                      style={
                        transferButton
                      }
                      onClick={() =>
                        abrirTransferencia(
                          "empleado",
                          empleado
                        )
                      }
                    >
                      🔁 Transferir
                    </button>
                  </div>
                )
              )}
            </div>
          )}
        </section>
      )}

      {/* ==============================================
          SIN PERMISO
      ============================================== */}

      {!puedeClinica &&
        !puedeRH && (
          <div
            style={
              emptyBox
            }
          >
            No tienes transferencias disponibles para tu área.
          </div>
        )}

      {/* ==============================================
          MODAL
      ============================================== */}

      {seleccionado && (
        <TransferirExpedienteModal
          abierto={
            mostrarModal
          }

          tipo={
            seleccionado.tipo
          }

          idExpediente={
            seleccionado.tipo ===
            "paciente"
              ? seleccionado
                  .item
                  .id_paciente
              : seleccionado
                  .item
                  .id_empleado
          }

          nombreExpediente={
            seleccionado
              .item
              .nombre
          }

          onClose={() => {
            setMostrarModal(
              false
            );

            setSeleccionado(
              null
            );
          }}

          onTransferido={
            transferenciaRealizada
          }
        />
      )}
    </div>
  );
}

// ==================================================
// ESTILOS
// ==================================================

const page = {
  minHeight:
    "100vh",

  padding:
    "32px",

  maxWidth:
    "1200px",

  margin:
    "0 auto",

  boxSizing:
    "border-box",

  fontFamily:
    "'Segoe UI', Arial, sans-serif",

  background:
    "#f7faff"
};

const header = {
  display:
    "flex",

  alignItems:
    "flex-start",

  gap:
    "20px",

  marginBottom:
    "24px"
};

const backButton = {
  border:
    "none",

  background:
    "#eef3f8",

  color:
    "#263238",

  padding:
    "10px 16px",

  borderRadius:
    "10px",

  cursor:
    "pointer",

  fontWeight:
    "700"
};

const label = {
  color:
    "#607d8b",

  fontSize:
    "12px",

  fontWeight:
    "800",

  letterSpacing:
    "1.2px",

  marginBottom:
    "4px"
};

const title = {
  margin:
    0,

  color:
    "#172b4d",

  fontSize:
    "30px"
};

const subtitle = {
  margin:
    "7px 0 0",

  color:
    "#78909c",

  fontSize:
    "14px",

  lineHeight:
    "1.5"
};

const notice = {
  background:
    "#fff8e6",

  border:
    "1px solid #f2d489",

  borderRadius:
    "14px",

  padding:
    "14px 16px",

  color:
    "#7a5a10",

  fontSize:
    "13px",

  lineHeight:
    "1.5",

  marginBottom:
    "28px"
};

const errorBox = {
  background:
    "#fff1f2",

  border:
    "1px solid #fecdd3",

  color:
    "#b42318",

  padding:
    "14px",

  borderRadius:
    "12px",

  marginBottom:
    "20px"
};

const section = {
  marginBottom:
    "34px"
};

const sectionHeader = {
  display:
    "flex",

  alignItems:
    "center",

  gap:
    "12px",

  marginBottom:
    "16px"
};

const sectionIcon = {
  width:
    "50px",

  height:
    "50px",

  borderRadius:
    "14px",

  background:
    "#eef4ff",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "24px"
};

const sectionTitle = {
  margin:
    0,

  color:
    "#263238",

  fontSize:
    "21px"
};

const sectionDescription = {
  margin:
    "4px 0 0",

  color:
    "#78909c",

  fontSize:
    "13px"
};

const list = {
  display:
    "flex",

  flexDirection:
    "column",

  gap:
    "12px"
};

const itemCard = {
  background:
    "#ffffff",

  border:
    "1px solid #e3eaf2",

  borderRadius:
    "16px",

  padding:
    "16px",

  display:
    "flex",

  alignItems:
    "center",

  gap:
    "14px",

  boxShadow:
    "0 4px 14px rgba(30,60,90,.06)"
};

const avatar = {
  width:
    "46px",

  height:
    "46px",

  borderRadius:
    "50%",

  background:
    "#eaf1ff",

  color:
    "#2167d5",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontWeight:
    "900",

  fontSize:
    "18px"
};

const avatarRH = {
  ...avatar,

  background:
    "#ecfdf3",

  color:
    "#067647"
};

const itemInfo = {
  flex:
    1,

  minWidth:
    0
};

const itemName = {
  margin:
    "0 0 5px",

  color:
    "#263238",

  fontSize:
    "16px"
};

const itemMeta = {
  color:
    "#607d8b",

  fontSize:
    "12px"
};

const itemSubMeta = {
  color:
    "#78909c",

  fontSize:
    "12px",

  marginTop:
    "3px"
};

const transferButton = {
  border:
    "1px solid #b9ddc5",

  background:
    "#ecfdf3",

  color:
    "#067647",

  borderRadius:
    "10px",

  padding:
    "10px 15px",

  cursor:
    "pointer",

  fontWeight:
    "800",

  fontSize:
    "13px",

  whiteSpace:
    "nowrap"
};

const emptyBox = {
  background:
    "#ffffff",

  border:
    "1px dashed #cbd5e1",

  borderRadius:
    "14px",

  padding:
    "26px",

  textAlign:
    "center",

  color:
    "#78909c",

  fontSize:
    "14px"
};

const loadingContainer = {
  textAlign:
    "center",

  padding:
    "90px 20px",

  color:
    "#607d8b"
};

const loadingIcon = {
  fontSize:
    "42px",

  marginBottom:
    "10px"
};