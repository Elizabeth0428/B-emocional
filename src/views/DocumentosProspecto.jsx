// ==================================================
// src/views/DocumentosProspecto.jsx
// ==================================================

import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  useNavigate,
  useParams
} from "react-router-dom";

import {
  getToken
} from "../services/AuthService";


const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);


// ==================================================
// DOCUMENTOS DEL PROSPECTO
// ==================================================

export default function DocumentosProspecto() {

  const {
    idProspecto
  } = useParams();

  const navigate =
    useNavigate();


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    prospecto,
    setProspecto
  ] = useState(null);

  const [
    documentos,
    setDocumentos
  ] = useState([]);

  const [
    archivo,
    setArchivo
  ] = useState(null);

  const [
    tipoDocumento,
    setTipoDocumento
  ] = useState("cv");

  const [
    descripcion,
    setDescripcion
  ] = useState("");

  const [
    loading,
    setLoading
  ] = useState(true);

  const [
    subiendo,
    setSubiendo
  ] = useState(false);

  const [
    abriendoId,
    setAbriendoId
  ] = useState(null);

  const [
    eliminandoId,
    setEliminandoId
  ] = useState(null);

  const [
    error,
    setError
  ] = useState("");

  const [
    mensaje,
    setMensaje
  ] = useState("");


  const token =
    getToken();


  // ==================================================
  // TIPOS
  // ==================================================

  const tipos = useMemo(
    () => [
      {
        value: "cv",
        label: "Currículum / CV",
        icon: "📄"
      },
      {
        value: "identificacion",
        label: "Identificación",
        icon: "🪪"
      },
      {
        value: "constancia",
        label: "Constancia",
        icon: "📋"
      },
      {
        value: "certificado",
        label: "Certificado",
        icon: "🎓"
      },
      {
        value: "comprobante",
        label: "Comprobante",
        icon: "🧾"
      },
      {
        value: "otro",
        label: "Otro documento",
        icon: "📎"
      }
    ],
    []
  );


  // ==================================================
  // OBTENER NOMBRE DEL TIPO
  // ==================================================

  const obtenerTipo =
    valor => {

      return (
        tipos.find(
          item =>
            item.value === valor
        ) || {
          label: valor || "Documento",
          icon: "📎"
        }
      );
    };


  // ==================================================
  // FORMATEAR FECHA
  // ==================================================

  const formatearFecha =
    fecha => {

      if (!fecha) {
        return "Sin fecha";
      }

      try {

        return new Date(
          fecha
        ).toLocaleString(
          "es-MX",
          {
            dateStyle: "medium",
            timeStyle: "short"
          }
        );

      } catch {

        return String(
          fecha
        );
      }
    };


  // ==================================================
  // FORMATEAR TAMAÑO
  // ==================================================

  const formatearMime =
    mime => {

      const mapa = {
        "application/pdf":
          "PDF",
        "image/jpeg":
          "Imagen JPG",
        "image/png":
          "Imagen PNG",
        "application/msword":
          "Documento Word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
          "Documento Word"
      };

      return (
        mapa[mime] ||
        mime ||
        "Archivo"
      );
    };


  // ==================================================
  // CARGAR DOCUMENTOS
  // ==================================================

  const cargarDocumentos =
    async () => {

      try {

        setLoading(true);
        setError("");


        if (!token) {

          throw new Error(
            "Tu sesión no es válida. Inicia sesión nuevamente."
          );
        }


        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/documentos`,
            {
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
            "No fue posible cargar los documentos."
          );
        }


        setProspecto(
          data.prospecto ||
          null
        );


        setDocumentos(
          Array.isArray(
            data.documentos
          )
            ? data.documentos
            : []
        );


      } catch (err) {

        console.error(
          "❌ Error cargando documentos:",
          err
        );

        setError(
          err.message ||
          "No fue posible cargar los documentos."
        );

      } finally {

        setLoading(false);
      }
    };


  // ==================================================
  // CARGAR AL ENTRAR
  // ==================================================

  useEffect(
    () => {

      if (idProspecto) {
        cargarDocumentos();
      }

    },
    [
      idProspecto
    ]
  );


  // ==================================================
  // SELECCIONAR ARCHIVO
  // ==================================================

  const seleccionarArchivo =
    event => {

      const seleccionado =
        event.target.files?.[0] ||
        null;


      setError("");
      setMensaje("");


      if (!seleccionado) {

        setArchivo(null);
        return;
      }


      const maximo =
        10 * 1024 * 1024;


      if (
        seleccionado.size >
        maximo
      ) {

        setArchivo(null);

        event.target.value =
          "";

        setError(
          "El archivo no puede superar los 10 MB."
        );

        return;
      }


      const extensiones =
        [
          ".pdf",
          ".jpg",
          ".jpeg",
          ".png",
          ".doc",
          ".docx"
        ];


      const nombre =
        seleccionado.name
          .toLowerCase();


      const valido =
        extensiones.some(
          extension =>
            nombre.endsWith(
              extension
            )
        );


      if (!valido) {

        setArchivo(null);

        event.target.value =
          "";

        setError(
          "Formato no permitido. Utiliza PDF, JPG, JPEG, PNG, DOC o DOCX."
        );

        return;
      }


      setArchivo(
        seleccionado
      );
    };


  // ==================================================
  // SUBIR DOCUMENTO
  // ==================================================

  const subirDocumento =
    async event => {

      event.preventDefault();


      if (!archivo) {

        setError(
          "Selecciona un documento antes de continuar."
        );

        return;
      }


      try {

        setSubiendo(true);
        setError("");
        setMensaje("");


        const formData =
          new FormData();


        formData.append(
          "file",
          archivo
        );

        formData.append(
          "tipo_documento",
          tipoDocumento
        );

        formData.append(
          "descripcion",
          descripcion.trim()
        );


        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/documentos`,
            {
              method:
                "POST",

              headers: {
                Authorization:
                  `Bearer ${token}`
              },

              body:
                formData
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
            "No fue posible subir el documento."
          );
        }


        setMensaje(
          "✅ Documento guardado correctamente."
        );


        setArchivo(null);
        setDescripcion("");
        setTipoDocumento("cv");


        const input =
          document.getElementById(
            "documento-rh-file"
          );


        if (input) {
          input.value = "";
        }


        await cargarDocumentos();


      } catch (err) {

        console.error(
          "❌ Error subiendo documento:",
          err
        );


        setError(
          err.message ||
          "No fue posible subir el documento."
        );

      } finally {

        setSubiendo(false);
      }
    };


  // ==================================================
  // ABRIR DOCUMENTO PROTEGIDO
  // ==================================================

  const abrirDocumento =
    async documento => {

      try {

        setAbriendoId(
          documento.id_documento
        );

        setError("");


        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/documentos/${documento.id_documento}/archivo`,
            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }
          );


        if (!response.ok) {

          const data =
            await response
              .json()
              .catch(
                () => ({})
              );


          throw new Error(
            data.message ||
            "No fue posible abrir el documento."
          );
        }


        const blob =
          await response.blob();


        const url =
          URL.createObjectURL(
            blob
          );


        window.open(
          url,
          "_blank",
          "noopener,noreferrer"
        );


        setTimeout(
          () => {
            URL.revokeObjectURL(
              url
            );
          },
          60000
        );


      } catch (err) {

        console.error(
          "❌ Error abriendo documento:",
          err
        );


        setError(
          err.message ||
          "No fue posible abrir el documento."
        );

      } finally {

        setAbriendoId(null);
      }
    };


  // ==================================================
  // DESCARGAR DOCUMENTO
  // ==================================================

  const descargarDocumento =
    async documento => {

      try {

        setAbriendoId(
          documento.id_documento
        );

        setError("");


        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/documentos/${documento.id_documento}/archivo`,
            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }
          );


        if (!response.ok) {

          throw new Error(
            "No fue posible descargar el documento."
          );
        }


        const blob =
          await response.blob();


        const url =
          URL.createObjectURL(
            blob
          );


        const link =
          document.createElement(
            "a"
          );


        link.href =
          url;

        link.download =
          documento.nombre_original ||
          "documento";

        document.body.appendChild(
          link
        );

        link.click();

        link.remove();


        URL.revokeObjectURL(
          url
        );


      } catch (err) {

        console.error(
          "❌ Error descargando documento:",
          err
        );


        setError(
          err.message ||
          "No fue posible descargar el documento."
        );

      } finally {

        setAbriendoId(null);
      }
    };


  // ==================================================
  // ELIMINAR
  // ==================================================

  const eliminarDocumento =
    async documento => {

      const confirmar =
        window.confirm(
          `¿Deseas eliminar "${documento.nombre_original}"?\n\nEsta acción eliminará el archivo del expediente.`
        );


      if (!confirmar) {
        return;
      }


      try {

        setEliminandoId(
          documento.id_documento
        );

        setError("");
        setMensaje("");


        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/documentos/${documento.id_documento}`,
            {
              method:
                "DELETE",

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
            "No fue posible eliminar el documento."
          );
        }


        setMensaje(
          "✅ Documento eliminado correctamente."
        );


        await cargarDocumentos();


      } catch (err) {

        console.error(
          "❌ Error eliminando documento:",
          err
        );


        setError(
          err.message ||
          "No fue posible eliminar el documento."
        );

      } finally {

        setEliminandoId(null);
      }
    };


  // ==================================================
  // CARGANDO
  // ==================================================

  if (loading) {

    return (

      <div style={centerPage}>

        <div style={loadingCard}>

          <div style={loadingIcon}>
            📁
          </div>

          <h2>
            Preparando documentos
          </h2>

          <p style={muted}>
            Cargando archivos del expediente...
          </p>

        </div>

      </div>
    );
  }


  // ==================================================
  // VISTA
  // ==================================================

  return (

    <div style={page}>


      {/* ==============================================
          HEADER
      ============================================== */}

      <div style={header}>

        <button
          type="button"
          style={backButton}
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}`
            )
          }
        >
          ⬅ Volver
        </button>


        <div style={{ flex: 1 }}>

          <div style={eyebrow}>
            RECURSOS HUMANOS
          </div>

          <h1 style={title}>
            📁 Documentos del prospecto
          </h1>

          <p style={subtitle}>

            Administra CV, identificaciones,
            constancias y documentos asociados
            al proceso de selección.

          </p>

        </div>

      </div>


      {/* ==============================================
          PROSPECTO
      ============================================== */}

      {prospecto && (

        <div style={prospectCard}>

          <div style={avatar}>

            {String(
              prospecto.nombre ||
              "P"
            )
              .charAt(0)
              .toUpperCase()}

          </div>


          <div>

            <div style={prospectName}>
              {prospecto.nombre}
            </div>

            <div style={prospectMeta}>
              🆔{" "}
              {prospecto.id_mirror ||
                `Prospecto #${idProspecto}`}
            </div>

          </div>


          <div style={documentCount}>

            <strong>
              {documentos.length}
            </strong>

            <span>
              documento
              {documentos.length !== 1
                ? "s"
                : ""}
            </span>

          </div>

        </div>
      )}


      {/* ==============================================
          MENSAJES
      ============================================== */}

      {error && (

        <div style={errorBox}>
          ⚠️ {error}
        </div>
      )}


      {mensaje && (

        <div style={successBox}>
          {mensaje}
        </div>
      )}


      {/* ==============================================
          SUBIR DOCUMENTO
      ============================================== */}

      <section style={uploadCard}>

        <div style={sectionHeader}>

          <div style={sectionIcon}>
            ⬆️
          </div>

          <div>

            <h2 style={sectionTitle}>
              Agregar documento
            </h2>

            <p style={sectionSubtitle}>
              El archivo quedará asociado al expediente
              de selección del prospecto.
            </p>

          </div>

        </div>


        <form
          onSubmit={subirDocumento}
        >

          <div style={formGrid}>


            {/* TIPO */}

            <div>

              <label style={label}>
                Tipo de documento
              </label>

              <select
                value={tipoDocumento}
                onChange={event =>
                  setTipoDocumento(
                    event.target.value
                  )
                }
                style={input}
              >

                {tipos.map(
                  tipo => (

                    <option
                      key={tipo.value}
                      value={tipo.value}
                    >
                      {tipo.icon}{" "}
                      {tipo.label}
                    </option>
                  )
                )}

              </select>

            </div>


            {/* ARCHIVO */}

            <div>

              <label style={label}>
                Archivo
              </label>

              <input
                id="documento-rh-file"
                type="file"
                accept=".pdf,.jpg,.jpeg,.png,.doc,.docx"
                onChange={
                  seleccionarArchivo
                }
                style={fileInput}
              />

            </div>

          </div>


          {/* ARCHIVO SELECCIONADO */}

          {archivo && (

            <div style={selectedFile}>

              <span style={selectedIcon}>
                📎
              </span>

              <div>

                <strong>
                  {archivo.name}
                </strong>

                <div style={selectedMeta}>
                  {(
                    archivo.size /
                    1024 /
                    1024
                  ).toFixed(2)}
                  {" MB"}
                </div>

              </div>

            </div>
          )}


          {/* DESCRIPCIÓN */}

          <div style={{ marginTop: 18 }}>

            <label style={label}>
              Descripción opcional
            </label>

            <textarea
              value={descripcion}
              onChange={event =>
                setDescripcion(
                  event.target.value
                )
              }
              placeholder="Ejemplo: CV actualizado recibido durante entrevista..."
              maxLength={500}
              rows={3}
              style={textarea}
            />

            <div style={characterCount}>
              {descripcion.length}/500
            </div>

          </div>


          <div style={uploadFooter}>

            <div style={uploadHelp}>
              🔒 PDF, JPG, PNG, DOC o DOCX · Máximo 10 MB
            </div>


            <button
              type="submit"
              disabled={
                subiendo ||
                !archivo
              }
              style={{
                ...primaryButton,

                opacity:
                  subiendo ||
                  !archivo
                    ? 0.6
                    : 1,

                cursor:
                  subiendo ||
                  !archivo
                    ? "not-allowed"
                    : "pointer"
              }}
            >
              {subiendo
                ? "⏳ Guardando..."
                : "⬆️ Guardar documento"}
            </button>

          </div>

        </form>

      </section>


      {/* ==============================================
          LISTADO
      ============================================== */}

      <section style={documentsCard}>

        <div style={sectionHeader}>

          <div style={sectionIconBlue}>
            📚
          </div>

          <div style={{ flex: 1 }}>

            <h2 style={sectionTitle}>
              Documentos registrados
            </h2>

            <p style={sectionSubtitle}>
              Evidencias y archivos conservados
              durante el proceso de selección.
            </p>

          </div>


          <div style={countBadge}>
            {documentos.length}
          </div>

        </div>


        {documentos.length === 0 ? (

          <div style={emptyBox}>

            <div style={emptyIcon}>
              📂
            </div>

            <h3 style={emptyTitle}>
              Todavía no hay documentos
            </h3>

            <p style={emptyText}>
              Cuando agregues el primer archivo,
              aparecerá aquí y también formará parte
              del expediente final del prospecto.
            </p>

          </div>

        ) : (

          <div style={documentsList}>

            {documentos.map(
              documento => {

                const tipo =
                  obtenerTipo(
                    documento.tipo_documento
                  );


                return (

                  <div
                    key={
                      documento.id_documento
                    }
                    style={documentRow}
                  >

                    <div style={fileIcon}>
                      {tipo.icon}
                    </div>


                    <div style={fileInfo}>

                      <div style={fileName}>
                        {documento.nombre_original}
                      </div>


                      <div style={fileBadges}>

                        <span style={typeBadge}>
                          {tipo.label}
                        </span>

                        <span style={mimeBadge}>
                          {formatearMime(
                            documento.mime_type
                          )}
                        </span>

                      </div>


                      {documento.descripcion && (

                        <div style={fileDescription}>
                          {documento.descripcion}
                        </div>
                      )}


                      <div style={fileDate}>
                        📅{" "}
                        {formatearFecha(
                          documento.fecha_subida
                        )}
                      </div>

                    </div>


                    <div style={actions}>


                      <button
                        type="button"
                        style={viewButton}
                        disabled={
                          abriendoId ===
                          documento.id_documento
                        }
                        onClick={() =>
                          abrirDocumento(
                            documento
                          )
                        }
                      >
                        {abriendoId ===
                        documento.id_documento
                          ? "⏳"
                          : "👁️"}{" "}
                        Ver
                      </button>


                      <button
                        type="button"
                        style={downloadButton}
                        disabled={
                          abriendoId ===
                          documento.id_documento
                        }
                        onClick={() =>
                          descargarDocumento(
                            documento
                          )
                        }
                      >
                        ⬇️ Descargar
                      </button>


                      <button
                        type="button"
                        style={deleteButton}
                        disabled={
                          eliminandoId ===
                          documento.id_documento
                        }
                        onClick={() =>
                          eliminarDocumento(
                            documento
                          )
                        }
                      >
                        {eliminandoId ===
                        documento.id_documento
                          ? "⏳"
                          : "🗑️"}{" "}
                        Eliminar
                      </button>

                    </div>

                  </div>
                );
              }
            )}

          </div>
        )}

      </section>


      {/* ==============================================
          AVISO
      ============================================== */}

      <div style={notice}>

        <span style={noticeIcon}>
          🔐
        </span>

        <div>

          <strong>
            Documentación protegida
          </strong>

          <div style={noticeText}>
            Estos archivos forman parte del expediente
            interno de selección y solamente deben ser
            consultados por personal autorizado.
          </div>

        </div>

      </div>

    </div>
  );
}


// ==================================================
// ESTILOS
// ==================================================

const page = {
  maxWidth: 1100,
  margin: "0 auto",
  padding: "30px 24px 60px",
  boxSizing: "border-box",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
  color: "#263238"
};

const centerPage = {
  minHeight: "65vh",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 30
};

const loadingCard = {
  width: "100%",
  maxWidth: 480,
  textAlign: "center",
  padding: 35,
  background: "#fff",
  borderRadius: 18,
  boxShadow:
    "0 8px 25px rgba(0,0,0,.08)"
};

const loadingIcon = {
  fontSize: 48,
  marginBottom: 10
};

const muted = {
  color: "#78909C"
};

const header = {
  display: "flex",
  gap: 18,
  alignItems: "flex-start",
  marginBottom: 24
};

const backButton = {
  border: "none",
  borderRadius: 10,
  background: "#EEF3F8",
  color: "#37474F",
  padding: "11px 15px",
  cursor: "pointer",
  fontWeight: 700
};

const eyebrow = {
  color: "#7540D5",
  fontSize: 11,
  fontWeight: 900,
  letterSpacing: "1.3px",
  marginBottom: 5
};

const title = {
  margin: 0,
  fontSize: 29,
  color: "#173F73"
};

const subtitle = {
  margin:
    "7px 0 0",
  color: "#607D8B",
  lineHeight: 1.5
};

const prospectCard = {
  display: "flex",
  alignItems: "center",
  gap: 15,
  background:
    "linear-gradient(135deg,#EEF4FF,#F8F5FF)",
  border:
    "1px solid #DBE4F3",
  borderRadius: 16,
  padding: 18,
  marginBottom: 22
};

const avatar = {
  width: 52,
  height: 52,
  minWidth: 52,
  borderRadius: 14,
  background:
    "linear-gradient(135deg,#536FD8,#3D9AE8)",
  color: "#fff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontWeight: 900,
  fontSize: 22
};

const prospectName = {
  fontWeight: 900,
  fontSize: 18,
  color: "#163A6B"
};

const prospectMeta = {
  marginTop: 3,
  color: "#607D8B",
  fontSize: 13
};

const documentCount = {
  marginLeft: "auto",
  display: "flex",
  flexDirection: "column",
  textAlign: "center",
  background: "#fff",
  borderRadius: 12,
  padding: "8px 15px",
  color: "#536FD8",
  fontSize: 12
};

const errorBox = {
  background: "#FFEBEE",
  color: "#C62828",
  border:
    "1px solid #FFCDD2",
  borderRadius: 10,
  padding: 13,
  marginBottom: 18
};

const successBox = {
  background: "#E8F5E9",
  color: "#2E7D32",
  border:
    "1px solid #C8E6C9",
  borderRadius: 10,
  padding: 13,
  marginBottom: 18
};

const uploadCard = {
  background: "#fff",
  border:
    "1px solid #E0E7EF",
  borderRadius: 18,
  padding: 22,
  boxShadow:
    "0 5px 17px rgba(30,60,90,.05)",
  marginBottom: 22
};

const documentsCard = {
  ...uploadCard
};

const sectionHeader = {
  display: "flex",
  alignItems: "center",
  gap: 13,
  marginBottom: 20
};

const sectionIcon = {
  width: 45,
  height: 45,
  minWidth: 45,
  borderRadius: 12,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  background: "#F3E9FF",
  fontSize: 20
};

const sectionIconBlue = {
  ...sectionIcon,
  background: "#E8F1FF"
};

const sectionTitle = {
  margin: 0,
  fontSize: 19,
  color: "#263238"
};

const sectionSubtitle = {
  margin:
    "4px 0 0",
  color: "#78909C",
  fontSize: 13
};

const formGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(260px,1fr))",
  gap: 17
};

const label = {
  display: "block",
  marginBottom: 7,
  fontSize: 13,
  fontWeight: 800,
  color: "#455A64"
};

const input = {
  width: "100%",
  padding: "12px 13px",
  border:
    "1px solid #CFD8DC",
  borderRadius: 9,
  background: "#fff",
  fontSize: 14,
  boxSizing: "border-box"
};

const fileInput = {
  ...input,
  padding: 9
};

const textarea = {
  ...input,
  resize: "vertical",
  minHeight: 85,
  fontFamily:
    "inherit"
};

const characterCount = {
  textAlign: "right",
  marginTop: 4,
  fontSize: 11,
  color: "#90A4AE"
};

const selectedFile = {
  display: "flex",
  alignItems: "center",
  gap: 11,
  marginTop: 16,
  padding: 13,
  background: "#F5F8FC",
  borderRadius: 10,
  border:
    "1px solid #E1E8EF"
};

const selectedIcon = {
  fontSize: 25
};

const selectedMeta = {
  marginTop: 2,
  color: "#78909C",
  fontSize: 12
};

const uploadFooter = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: 15,
  flexWrap: "wrap",
  marginTop: 18
};

const uploadHelp = {
  fontSize: 12,
  color: "#78909C"
};

const primaryButton = {
  border: "none",
  borderRadius: 10,
  padding:
    "12px 18px",
  background: "#2167D5",
  color: "#fff",
  fontWeight: 800,
  boxShadow:
    "0 5px 13px rgba(33,103,213,.2)"
};

const countBadge = {
  marginLeft: "auto",
  minWidth: 33,
  height: 33,
  borderRadius: 17,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  background: "#EEF4FF",
  color: "#2167D5",
  fontWeight: 800
};

const emptyBox = {
  textAlign: "center",
  padding: "38px 20px",
  background: "#F8FAFC",
  borderRadius: 13,
  border:
    "1px dashed #CFD8DC"
};

const emptyIcon = {
  fontSize: 42
};

const emptyTitle = {
  margin:
    "9px 0 5px"
};

const emptyText = {
  margin: "0 auto",
  maxWidth: 500,
  color: "#78909C",
  lineHeight: 1.6,
  fontSize: 14
};

const documentsList = {
  display: "flex",
  flexDirection: "column",
  gap: 12
};

const documentRow = {
  display: "flex",
  alignItems: "center",
  gap: 14,
  padding: 15,
  background: "#FAFBFC",
  border:
    "1px solid #E4E9EF",
  borderRadius: 13,
  flexWrap: "wrap"
};

const fileIcon = {
  width: 45,
  height: 45,
  minWidth: 45,
  borderRadius: 11,
  background: "#EEF4FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 21
};

const fileInfo = {
  flex: 1,
  minWidth: 210
};

const fileName = {
  fontWeight: 800,
  color: "#263238",
  wordBreak: "break-word"
};

const fileBadges = {
  display: "flex",
  flexWrap: "wrap",
  gap: 6,
  marginTop: 6
};

const typeBadge = {
  display: "inline-block",
  padding: "4px 8px",
  borderRadius: 10,
  background: "#EEE8FF",
  color: "#6840B5",
  fontSize: 11,
  fontWeight: 800
};

const mimeBadge = {
  ...typeBadge,
  background: "#E8F3FF",
  color: "#2167D5"
};

const fileDescription = {
  marginTop: 7,
  color: "#546E7A",
  fontSize: 13,
  lineHeight: 1.45
};

const fileDate = {
  marginTop: 7,
  color: "#90A4AE",
  fontSize: 11
};

const actions = {
  display: "flex",
  gap: 7,
  flexWrap: "wrap"
};

const actionBase = {
  border: "none",
  borderRadius: 8,
  padding:
    "9px 11px",
  fontWeight: 700,
  cursor: "pointer",
  fontSize: 12
};

const viewButton = {
  ...actionBase,
  background: "#E8F1FF",
  color: "#2167D5"
};

const downloadButton = {
  ...actionBase,
  background: "#E8F5E9",
  color: "#2E7D32"
};

const deleteButton = {
  ...actionBase,
  background: "#FFEBEE",
  color: "#C62828"
};

const notice = {
  display: "flex",
  gap: 12,
  padding: 16,
  marginTop: 20,
  borderRadius: 13,
  background: "#FFF8E1",
  border:
    "1px solid #FFE082",
  color: "#6D4C41"
};

const noticeIcon = {
  fontSize: 22
};

const noticeText = {
  marginTop: 4,
  fontSize: 13,
  lineHeight: 1.5
};