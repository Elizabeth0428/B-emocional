import React,{useEffect,useState} from "react";
import {getToken} from "../services/AuthService";
import {useNavigate,useParams} from "react-router-dom";

const API_URL=import.meta.env.VITE_API_URL||"http://localhost:5000";

export default function DetalleProspecto({idProspecto:idProp,prospecto:prop,onBack}){
  const navigate=useNavigate();
  const {idProspecto:idRuta}=useParams();
  const idProspecto=idProp||idRuta||prop?.id_prospecto||prop?.id;
  const [prospecto,setProspecto]=useState(prop||null);
  const [loading,setLoading]=useState(!prop);
  const [error,setError]=useState("");

  useEffect(()=>{
    if(prop){setLoading(false);return;}
    if(!idProspecto){setLoading(false);setError("No se recibió el identificador del prospecto.");return;}

    const obtener=async()=>{
      try{
        setLoading(true);setError("");
        const r=await fetch(`${API_URL}/api/prospectos-rh/${idProspecto}`,{
          method:"GET",
          headers:{Authorization:`Bearer ${getToken()}`,"Content-Type":"application/json"}
        });
        const data=await r.json();
        if(!r.ok)throw new Error(data.message||"No se pudo obtener el expediente del prospecto.");
        setProspecto(data.prospecto||data.data||data);
      }catch(err){
        console.error("❌ Error al obtener expediente:",err);
        if(!prop)setError(err.message||"No se pudo cargar el expediente.");
      }finally{setLoading(false);}
    };

    obtener();
  },[idProspecto,prop]);

  const volver=()=>onBack?onBack():navigate("/prospectos-rh");
  const irA=ruta=>navigate(`/prospecto/${idProspecto}${ruta}`);

  const obtenerEstado=()=>{
    const e=String(prospecto?.estatus||prospecto?.estado||"prospecto").trim().toLowerCase();
    const estados={
      prospecto:{texto:"Prospecto",fondo:"#FFF7E6",color:"#B7791F"},
      en_proceso:{texto:"En proceso de selección",fondo:"#EEF4FF",color:"#2167D5"},
      evaluacion:{texto:"En evaluación",fondo:"#F3E9FF",color:"#7540D5"},
      aprobado:{texto:"Aprobado",fondo:"#ECF9EF",color:"#3BAE55"},
      contratado:{texto:"Contratado",fondo:"#E8F8ED",color:"#27843A"},
      no_contratado:{texto:"No contratado",fondo:"#FFF1F1",color:"#C62828"}
    };
    return estados[e]||estados.prospecto;
  };

  if(loading)return(
    <div style={loadingContainer}>
      <div style={loadingIcon}>⏳</div>
      <h3>Cargando expediente...</h3>
      <p>Estamos obteniendo la información del prospecto.</p>
    </div>
  );

  if((error&&!prospecto)||!prospecto)return(
    <div style={errorContainer}>
      <div style={errorIcon}>{error?"⚠️":"👤"}</div>
      <h2>{error?"No se pudo cargar el expediente":"Prospecto no encontrado"}</h2>
      <p>{error||"No fue posible obtener la información del expediente."}</p>
      <button type="button" onClick={volver} style={backButton}>⬅ Volver a prospectos</button>
    </div>
  );

  const estado=obtenerEstado();
  const nombre=prospecto.nombre||"Prospecto sin nombre";
  const idMirror=prospecto.id_mirror||prospecto.mirror_id||prospecto.codigo||"RH-2026-001";
  const sexo=prospecto.sexo||prospecto.genero||"No especificado";
  const edad=prospecto.edad??"No especificada";
  const correo=prospecto.correo||"No registrado";
  const telefono=prospecto.telefono||"No registrado";
  const direccion=prospecto.direccion||"No registrada";
  const puesto=prospecto.puesto||prospecto.puesto_aspira||prospecto.puesto_al_que_aspira||"No registrado";
  const area=prospecto.area||prospecto.area_puesto||"No registrada";
  const fechaRegistro=prospecto.fecha_registro?new Date(prospecto.fecha_registro).toLocaleDateString("es-MX"):"No disponible";

  return(
    <div style={page}>
      <div style={header}>
        <button type="button" onClick={volver} style={backButton}>⬅ Volver</button>
        <div style={headerInfo}>
          <div style={headerLabel}>EXPEDIENTE DEL PROSPECTO</div>
          <h1 style={title}>👤 {nombre}</h1>
          <div style={mirrorId}>🆔 {idMirror}</div>
        </div>
      </div>

      <div style={statusContainer}>
        <div>
          <div style={statusLabel}>ESTADO DEL PROCESO</div>
          <strong style={{...statusBadge,background:estado.fondo,color:estado.color}}>{estado.texto}</strong>
        </div>
        <div style={decisionInfo}>
          <span style={decisionIcon}>🏢</span>
          <div>
            <strong>Decisión de RH</strong>
            <p>La decisión final de contratación corresponde exclusivamente a Recursos Humanos.</p>
          </div>
        </div>
      </div>

      <section style={section}>
        <SectionHeader icon="👤" title="Información personal" description="Información registrada del prospecto."/>
        <div style={infoGrid}>
          <InfoItem icon="👤" label="Nombre" value={nombre}/>
          <InfoItem icon="⚧" label="Sexo" value={sexo}/>
          <InfoItem icon="🎂" label="Edad" value={edad!=="No especificada"?`${edad} años`:edad}/>
          <InfoItem icon="📧" label="Correo" value={correo}/>
          <InfoItem icon="📞" label="Teléfono" value={telefono}/>
          <InfoItem icon="📍" label="Dirección" value={direccion}/>
        </div>
      </section>

      <section style={section}>
        <SectionHeader icon="💼" title="Información del puesto" description="Datos relacionados con la vacante a la que aspira."/>
        <div style={infoGrid}>
          <InfoItem icon="💼" label="Puesto al que aspira" value={puesto}/>
          <InfoItem icon="🏢" label="Área" value={area}/>
          <InfoItem icon="📅" label="Fecha de registro" value={fechaRegistro}/>
          <InfoItem icon="📌" label="Estado del proceso" value={estado.texto}/>
        </div>
      </section>

      <section style={section}>
        <SectionHeader icon="📋" title="Proceso de selección" description="Consulta y administra cada etapa del proceso."/>
        <div style={modulesGrid}>
          <ModuleCard icon="📋" title="Seguimiento" description="Consulta la evolución del proceso de selección y las etapas realizadas." button="Consultar" onClick={()=>irA("/seguimiento")}/>
          <ModuleCard icon="📅" title="Entrevistas / citas" description="Consulta y administra las entrevistas realizadas durante el proceso." button="Consultar" onClick={()=>irA("/entrevistas")}/>
          <ModuleCard icon="🧪" title="Pruebas psicométricas" description="Habilita, administra y consulta las pruebas realizadas por el prospecto." button="Administrar pruebas" accent="purple" onClick={()=>irA("/pruebas")}/>
          <ModuleCard icon="🎥" title="Videollamada" description="Realiza una entrevista por videollamada cuando sea necesario. La sesión puede quedar grabada." button="Abrir videollamada" onClick={()=>navigate(`/SalaVideollamada/nueva/prospecto/${idProspecto}`)}/>
          <ModuleCard icon="📄" title="Documentos" description="Consulta los documentos asociados al proceso de selección." button="Consultar" onClick={()=>irA("/documentos")}/>
          <ModuleCard icon="📝" title="Observaciones de RH" description="Registra las observaciones obtenidas durante entrevistas o cualquier otra etapa." button="Registrar observaciones" accent="green" onClick={()=>irA("/observaciones")}/>
        </div>
      </section>

      <section style={section}>
        <div style={aiSection}>
          <div style={aiHeader}>
            <div style={aiIcon}>🧠</div>
            <div>
              <h2 style={aiTitle}>Análisis del proceso con IA</h2>
              <p style={aiDescription}>La IA analiza la información disponible del expediente para generar un preanálisis que apoye la evaluación de RH.</p>
            </div>
          </div>

          <div style={aiSources}>
            <div style={aiSourceTitle}>La IA puede considerar:</div>
            <div style={aiSourceGrid}>
              <AiSource icon="👤" text="Datos registrados por RH"/>
              <AiSource icon="📋" text="Seguimiento del proceso"/>
              <AiSource icon="📅" text="Entrevistas"/>
              <AiSource icon="📝" text="Observaciones de RH"/>
              <AiSource icon="🧪" text="Resultados de pruebas psicométricas"/>
              <AiSource icon="🎥" text="Videollamadas y material disponible"/>
              <AiSource icon="📄" text="Documentación relevante"/>
              <AiSource icon="💼" text="Perfil y puesto al que aspira"/>
            </div>
          </div>

          <div style={aiNotice}>
            <div style={aiNoticeIcon}>⚠️</div>
            <div>
              <strong>La IA no toma la decisión de contratación.</strong>
              <p>El análisis generado por IA funciona como apoyo para RH. La decisión final corresponde a Recursos Humanos.</p>
            </div>
          </div>

          <button type="button" style={aiButton} onClick={()=>irA("/reporte-ia")}>
            🧠 Abrir análisis y reporte IA <span>→</span>
          </button>
        </div>
      </section>

      <section style={section}>
        <div style={decisionCard}>
          <div style={decisionHeader}>
            <div style={decisionBigIcon}>⚖️</div>
            <div>
              <h2 style={decisionTitle}>Decisión de Recursos Humanos</h2>
              <p style={decisionDescription}>Después de revisar la información, entrevistas, observaciones y resultados de las pruebas, RH determina el resultado final del proceso.</p>
            </div>
          </div>

          <div style={decisionButtons}>
            <button type="button" style={approveButton} onClick={()=>irA("/decision?resultado=contratar")}>✅ Contratar</button>
            <button type="button" style={rejectButton} onClick={()=>irA("/decision?resultado=no_contratar")}>❌ No contratar</button>
          </div>

          <div style={decisionFooter}>💡 Si RH decide contratar al prospecto, posteriormente podrá convertirse en empleado conservando la información y el historial registrado durante el proceso.</div>
        </div>
      </section>

      <footer style={footer}>
        <span>🧠 MirrorSoul</span>
        <span>Expediente del prospecto #{idProspecto}</span>
      </footer>
    </div>
  );
}

function SectionHeader({icon,title,description}){
  return <div style={sectionHeader}><div style={sectionHeaderIcon}>{icon}</div><div><h2 style={sectionTitle}>{title}</h2><p style={sectionDescription}>{description}</p></div></div>;
}

function InfoItem({icon,label,value}){
  return <div style={infoItem}><div style={infoIcon}>{icon}</div><div style={infoContent}><div style={infoLabel}>{label}</div><div style={infoValue}>{value}</div></div></div>;
}

function ModuleCard({icon,title,description,button,onClick,accent="blue"}){
  const accents={
    blue:{background:"#EEF4FF",color:"#2167D5",button:"#2167D5"},
    purple:{background:"#F3E9FF",color:"#7540D5",button:"#7540D5"},
    green:{background:"#ECF9EF",color:"#3BAE55",button:"#3BAE55"}
  };
  const c=accents[accent]||accents.blue;

  return <div style={moduleCard}>
    <div style={{...moduleIcon,background:c.background,color:c.color}}>{icon}</div>
    <div style={moduleContent}>
      <h3 style={moduleTitle}>{title}</h3>
      <p style={moduleDescription}>{description}</p>
      <button type="button" onClick={onClick} style={{...moduleButton,background:c.button}}>{button}<span>→</span></button>
    </div>
  </div>;
}

function AiSource({icon,text}){
  return <div style={aiSource}><span style={aiSourceIcon}>{icon}</span><span>{text}</span></div>;
}

const page={minHeight:"100vh",padding:30,maxWidth:1200,margin:"0 auto",boxSizing:"border-box",fontFamily:"'Segoe UI',Arial,sans-serif",color:"#263238",background:"#F8FAFD"};
const header={display:"flex",alignItems:"center",gap:25,marginBottom:25};
const headerInfo={flex:1};
const backButton={border:"none",background:"#EEF3F8",color:"#263238",padding:"10px 16px",borderRadius:10,cursor:"pointer",fontWeight:600,fontSize:14};
const headerLabel={color:"#607D8B",fontSize:12,fontWeight:700,letterSpacing:"1.2px",marginBottom:5};
const title={margin:0,color:"#263238",fontSize:30,fontWeight:700};
const mirrorId={marginTop:7,display:"inline-block",background:"#E8F1FF",color:"#1565C0",padding:"6px 12px",borderRadius:8,fontSize:13,fontWeight:700};
const statusContainer={background:"#FFF",border:"1px solid #E1E8EF",borderRadius:18,padding:20,marginBottom:30,display:"flex",justifyContent:"space-between",alignItems:"center",gap:20,flexWrap:"wrap",boxShadow:"0 5px 18px rgba(30,60,90,.05)"};
const statusLabel={color:"#90A4AE",fontSize:11,fontWeight:800,letterSpacing:1,marginBottom:8};
const statusBadge={display:"inline-block",padding:"8px 14px",borderRadius:20,fontSize:13,fontWeight:800};
const decisionInfo={display:"flex",alignItems:"center",gap:12,maxWidth:500};
const decisionIcon={width:45,height:45,borderRadius:12,background:"#EEF4FF",display:"flex",alignItems:"center",justifyContent:"center",fontSize:21};
const section={marginBottom:35};
const sectionHeader={display:"flex",alignItems:"flex-start",gap:12,marginBottom:18};
const sectionHeaderIcon={fontSize:25};
const sectionTitle={margin:0,fontSize:21,color:"#263238"};
const sectionDescription={margin:"5px 0 0",color:"#78909C",fontSize:14};
const infoGrid={display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(250px,1fr))",gap:15};
const infoItem={display:"flex",alignItems:"center",gap:12,background:"#FFF",border:"1px solid #E1E8EF",padding:16,borderRadius:14,boxShadow:"0 4px 12px rgba(30,60,90,.04)"};
const infoIcon={minWidth:40,width:40,height:40,borderRadius:11,background:"#EEF4FF",display:"flex",alignItems:"center",justifyContent:"center",fontSize:18};
const infoContent={minWidth:0};
const infoLabel={color:"#90A4AE",fontSize:12,marginBottom:4};
const infoValue={color:"#263238",fontWeight:600,fontSize:14,wordBreak:"break-word"};
const modulesGrid={display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:18};
const moduleCard={display:"flex",alignItems:"flex-start",gap:17,background:"#FFF",border:"1px solid #E1E8EF",borderRadius:16,padding:22,boxShadow:"0 4px 14px rgba(30,60,90,.05)"};
const moduleIcon={minWidth:52,width:52,height:52,borderRadius:14,display:"flex",alignItems:"center",justifyContent:"center",fontSize:24};
const moduleContent={flex:1};
const moduleTitle={margin:"0 0 7px",fontSize:17,color:"#263238"};
const moduleDescription={margin:"0 0 15px",color:"#78909C",fontSize:13,lineHeight:1.5};
const moduleButton={border:"none",color:"#FFF",borderRadius:9,padding:"10px 13px",cursor:"pointer",fontWeight:700,display:"flex",alignItems:"center",justifyContent:"space-between",width:"100%"};
const aiSection={background:"linear-gradient(135deg,#F7F1FF,#FFF)",border:"1px solid #E2D3FA",borderRadius:20,padding:26,boxShadow:"0 7px 22px rgba(117,64,213,.08)"};
const aiHeader={display:"flex",alignItems:"center",gap:15,marginBottom:25};
const aiIcon={width:58,height:58,borderRadius:16,background:"#E9DDFB",display:"flex",alignItems:"center",justifyContent:"center",fontSize:27};
const aiTitle={margin:0,color:"#7540D5",fontSize:21};
const aiDescription={margin:"6px 0 0",color:"#6B7280",lineHeight:1.5,fontSize:14};
const aiSources={background:"#FFF",borderRadius:15,padding:18,marginBottom:18};
const aiSourceTitle={fontWeight:800,color:"#334155",marginBottom:13};
const aiSourceGrid={display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(210px,1fr))",gap:10};
const aiSource={display:"flex",alignItems:"center",gap:9,background:"#F8FAFC",padding:10,borderRadius:9,fontSize:13,color:"#475569"};
const aiSourceIcon={fontSize:17};
const aiNotice={display:"flex",alignItems:"flex-start",gap:12,background:"#FFF9E8",border:"1px solid #F3E2A5",borderRadius:12,padding:15,marginBottom:18,color:"#6B5A16"};
const aiNoticeIcon={fontSize:20};
const aiButton={width:"100%",border:"none",background:"#7540D5",color:"#FFF",padding:"13px 16px",borderRadius:10,cursor:"pointer",fontWeight:800,display:"flex",justifyContent:"space-between",alignItems:"center"};
const decisionCard={background:"#FFF",border:"1px solid #DDE5EC",borderRadius:20,padding:25,boxShadow:"0 6px 20px rgba(30,60,90,.06)"};
const decisionHeader={display:"flex",alignItems:"flex-start",gap:15};
const decisionBigIcon={width:55,height:55,borderRadius:15,background:"#EEF4FF",display:"flex",alignItems:"center",justifyContent:"center",fontSize:25};
const decisionTitle={margin:0,fontSize:20,color:"#263238"};
const decisionDescription={margin:"7px 0 0",color:"#78909C",lineHeight:1.5,fontSize:14};
const decisionButtons={display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:15,marginTop:22};
const approveButton={border:"none",background:"#3BAE55",color:"#FFF",padding:13,borderRadius:10,cursor:"pointer",fontWeight:800,fontSize:14};
const rejectButton={border:"none",background:"#C62828",color:"#FFF",padding:13,borderRadius:10,cursor:"pointer",fontWeight:800,fontSize:14};
const decisionFooter={marginTop:18,padding:13,background:"#F8FAFC",borderRadius:10,color:"#64748B",fontSize:13,lineHeight:1.5};
const footer={borderTop:"1px solid #E5E9EF",marginTop:35,paddingTop:18,display:"flex",justifyContent:"space-between",color:"#90A4AE",fontSize:12};
const loadingContainer={textAlign:"center",padding:"80px 20px",color:"#607D8B"};
const loadingIcon={fontSize:40,marginBottom:10};
const errorContainer={maxWidth:600,margin:"80px auto",textAlign:"center",background:"#FFF",padding:40,borderRadius:16,boxShadow:"0 5px 20px rgba(0,0,0,.08)"};
const errorIcon={fontSize:45,marginBottom:10};

export {DetalleProspecto};