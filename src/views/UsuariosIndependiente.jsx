// src/views/UsuariosIndependiente.jsx

import React, {
  useEffect,
  useState
} from "react";


const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://www.reflejoyalma.com";


const UsuariosIndependiente = ({
  onBack
}) => {

  const [
    usuarios,
    setUsuarios
  ] =
    useState([]);


  const [
    busqueda,
    setBusqueda
  ] =
    useState("");


  const [
    loading,
    setLoading
  ] =
    useState(true);


  const [
    error,
    setError
  ] =
    useState("");


  // ==================================================
  // CARGAR USUARIOS INDEPENDIENTES
  // ==================================================

  const cargarUsuarios =
    async () => {

      try {

        setLoading(
          true
        );

        setError(
          ""
        );


        const token =
          localStorage.getItem(
            "token"
          );


        const response =
          await fetch(
            `${API_URL}/api/usuario-independiente`,
            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }
          );


        const data =
          await response.json();


        if (
          !response.ok
        ) {

          throw new Error(
            data.message ||
            "Error al obtener usuarios"
          );

        }


        setUsuarios(
          Array.isArray(
            data
          )
            ? data
            : Array.isArray(
                data?.usuarios
              )
            ? data.usuarios
            : []
        );

      }

      catch (
        err
      ) {

        console.error(
          "❌ Error cargando usuarios independientes:",
          err
        );


        setError(
          err.message ||
          "No se pudieron cargar los usuarios independientes."
        );

      }

      finally {

        setLoading(
          false
        );

      }

    };


  // ==================================================
  // CARGA INICIAL
  // ==================================================

  useEffect(
    () => {

      cargarUsuarios();

    },
    []
  );


  // ==================================================
  // FILTRAR USUARIOS
  // ==================================================

  const filtrados =
    usuarios.filter(
      usuario => {

        const texto =
          busqueda
            .toLowerCase()
            .trim();


        if (
          !texto
        ) {

          return true;

        }


        return (

          String(
            usuario.nombre ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            )

          ||

          String(
            usuario.correo ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            )

          ||

          String(
            usuario.especialidad ||
            usuario.puesto ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            )

          ||

          String(
            usuario.telefono ||
            ""
          )
            .toLowerCase()
            .includes(
              texto
            )

        );

      }
    );


  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div
      style={
        container
      }
    >

      {/* ==================================================
          HEADER
      ================================================== */}

      <div
        style={
          header
        }
      >

        <button
          type="button"
          onClick={
            onBack
          }
          style={
            backButton
          }
        >
          ← Volver
        </button>


        <div>

          <h2
            style={
              title
            }
          >
            👤 Usuarios independientes
          </h2>


          <p
            style={
              subtitle
            }
          >
            Usuarios independientes registrados
            en MirrorSoul.
          </p>

        </div>

      </div>


      {/* ==================================================
          BUSCADOR
      ================================================== */}

      <input
        type="text"
        value={
          busqueda
        }
        onChange={
          e =>
            setBusqueda(
              e.target.value
            )
        }
        placeholder="🔎 Buscar usuario..."
        style={
          searchInput
        }
      />


      {/* ==================================================
          CONTADOR
      ================================================== */}

      <p
        style={
          counter
        }
      >

        Mostrando{" "}

        <strong>
          {filtrados.length}
        </strong>

        {" "}de{" "}

        <strong>
          {usuarios.length}
        </strong>

        {" "}usuarios

      </p>


      {/* ==================================================
          CARGANDO
      ================================================== */}

      {loading && (

        <div
          style={
            empty
          }
        >
          Cargando usuarios...
        </div>

      )}


      {/* ==================================================
          ERROR
      ================================================== */}

      {!loading &&
        error && (

        <div
          style={
            errorBox
          }
        >
          ❌ {error}
        </div>

      )}


      {/* ==================================================
          SIN RESULTADOS
      ================================================== */}

      {!loading &&
        !error &&
        filtrados.length ===
          0 && (

          <div
            style={
              empty
            }
          >
            👤 No hay usuarios independientes
            registrados.
          </div>

        )}


      {/* ==================================================
          LISTADO
      ================================================== */}

      {!loading &&
        !error &&
        filtrados.length >
          0 && (

          <div
            style={
              grid
            }
          >

            {filtrados.map(
              usuario => (

                <div
                  key={
                    usuario.id_usuario
                  }
                  style={
                    card
                  }
                >

                  <div
                    style={
                      cardTop
                    }
                  >

                    <div
                      style={
                        avatar
                      }
                    >
                      👤
                    </div>


                    <span
                      style={
                        badge
                      }
                    >
                      Independiente
                    </span>

                  </div>


                  <h3
                    style={
                      name
                    }
                  >
                    {usuario.nombre ||
                      "Sin nombre"}
                  </h3>


                  <div
                    style={
                      infoGroup
                    }
                  >

                    <p
                      style={
                        data
                      }
                    >
                      📧{" "}
                      {usuario.correo ||
                        "Sin correo"}
                    </p>


                    <p
                      style={
                        data
                      }
                    >
                      🧠{" "}
                      {usuario.especialidad ||
                        usuario.puesto ||
                        "Profesional independiente"}
                    </p>


                    <p
                      style={
                        data
                      }
                    >
                      📞{" "}
                      {usuario.telefono ||
                        "Sin teléfono"}
                    </p>


                    {usuario.direccion && (

                      <p
                        style={
                          data
                        }
                      >
                        📍{" "}
                        {usuario.direccion}
                      </p>

                    )}


                    {usuario.estado && (

                      <p
                        style={
                          data
                        }
                      >
                        Estado:{" "}

                        <strong>
                          {usuario.estado}
                        </strong>
                      </p>

                    )}

                  </div>

                </div>

              )
            )}

          </div>

        )}

    </div>

  );

};


// ==================================================
// ESTILOS
// ==================================================

const container = {
  maxWidth:
    "1150px",

  margin:
    "0 auto",

  padding:
    "40px",

  fontFamily:
    "'Segoe UI', Arial, sans-serif"
};


const header = {
  display:
    "flex",

  alignItems:
    "center",

  gap:
    "20px",

  marginBottom:
    "30px"
};


const backButton = {
  border:
    "none",

  background:
    "#EEF4FF",

  color:
    "#2167D5",

  padding:
    "10px 16px",

  borderRadius:
    "10px",

  cursor:
    "pointer",

  fontWeight:
    "700"
};


const title = {
  margin:
    0,

  color:
    "#172B4D"
};


const subtitle = {
  margin:
    "6px 0 0",

  color:
    "#718096"
};


const searchInput = {
  width:
    "100%",

  boxSizing:
    "border-box",

  padding:
    "14px",

  borderRadius:
    "10px",

  border:
    "1px solid #D9E2EF",

  fontSize:
    "15px",

  outline:
    "none"
};


const counter = {
  margin:
    "18px 0",

  color:
    "#596B82"
};


const grid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(260px, 1fr))",

  gap:
    "22px"
};


const card = {
  background:
    "#FFFFFF",

  padding:
    "25px",

  borderRadius:
    "18px",

  boxShadow:
    "0 8px 22px rgba(40,80,140,0.08)",

  border:
    "1px solid #EDF2F7",

  borderBottom:
    "4px solid #4A7FF5"
};


const cardTop = {
  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "space-between",

  gap:
    "12px"
};


const avatar = {
  width:
    "65px",

  height:
    "65px",

  borderRadius:
    "50%",

  background:
    "#EAF1FF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "30px"
};


const name = {
  margin:
    "18px 0 12px",

  color:
    "#2167D5"
};


const infoGroup = {
  display:
    "grid",

  gap:
    "3px"
};


const data = {
  margin:
    "5px 0",

  color:
    "#596B82",

  fontSize:
    "14px",

  lineHeight:
    1.5,

  wordBreak:
    "break-word"
};


const badge = {
  display:
    "inline-block",

  padding:
    "7px 10px",

  borderRadius:
    "20px",

  background:
    "#EEF7FF",

  color:
    "#2167D5",

  fontSize:
    "12px",

  fontWeight:
    "700"
};


const empty = {
  padding:
    "50px",

  textAlign:
    "center",

  color:
    "#718096"
};


const errorBox = {
  padding:
    "15px",

  borderRadius:
    "10px",

  background:
    "#FFF1F1",

  color:
    "#C62828"
};


export default UsuariosIndependiente;