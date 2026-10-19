// src/views/Dashboard.jsx

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  getCurrentUser,
  getToken
} from "../services/AuthService";

import Avatar from "../components/Avatar.jsx";
import WorkflowGuide from "../components/WorkflowGuide.jsx";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const Dashboard = ({ onNavigate }) => {
  const navigate = useNavigate();
  const user = getCurrentUser();

  const emojis = [
    "😀",
    "😎",
    "🤓",
    "🧠",
    "😄",
    "😊",
    "🙌",
    "🌈",
    "🌟",
    "💡",
    "🎯"
  ];

  const [emoji, setEmoji] =
    useState("😀");

  useEffect(() => {
    const interval =
      setInterval(() => {
        setEmoji(
          emojis[
            Math.floor(
              Math.random() *
              emojis.length
            )
          ]
        );
      }, 3000);

    return () =>
      clearInterval(interval);
  }, []);

  const handleHoverEmoji = () => {
    setEmoji(
      emojis[
        Math.floor(
          Math.random() *
          emojis.length
        )
      ]
    );
  };

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
      ? String(user.area)
          .trim()
          .toLowerCase()
      : null;

  const rol =
    user?.rol
      ? String(user.rol)
          .trim()
          .toLowerCase()
      : null;

  const esMaster =
    user?.role === 1 &&
    tipoAdmin === "master";

  const esAdminNormal =
    user?.role === 1 &&
    tipoAdmin === "normal";

  const esPsicologo =
    user?.role === 2 &&
    rol === "psicologo";

  const esUsuarioRH =
    user?.role === 2 &&
    rol === "rh";

  const esUsuarioEducativo =
    user?.role === 2 &&
    rol === "educativo";

  const esUsuarioIndependiente =
    user?.role === 2 &&
    rol === "independiente";

  const [
    stats,
    setStats
  ] = useState({
    pacientes: 0,

    prospectos: 0,
    prospectosActivos: 0,
    empleados: 0,

    citas: 0,
    proximaCita: null,
    sesionesAbiertas: 0,
    seguimientosPendientes: 0,
    pruebasPendientes: 0,
    preanalisisPendientes: 0
  });

  const [
    statsLoading,
    setStatsLoading
  ] = useState(true);

  useEffect(() => {
    const cargarDatos =
      async () => {
        try {
          setStatsLoading(true);

          const token =
            getToken();

          if (!token) {
            return;
          }

          if (esPsicologo) {
            const response =
              await fetch(
                `${API_URL}/api/pacientes`,
                {
                  headers: {
                    Authorization:
                      `Bearer ${token}`
                  }
                }
              );

            if (response.ok) {
              const data =
                await response.json();

              const lista =
                Array.isArray(data)
                  ? data
                  : Array.isArray(
                      data?.pacientes
                    )
                  ? data.pacientes
                  : [];

              setStats(
                prev => ({
                  ...prev,
                  pacientes:
                    lista.length
                })
              );
            }
          }

          if (esUsuarioRH) {
            const [
              respuestaProspectos,
              respuestaEmpleados
            ] =
              await Promise.allSettled([
                fetch(
                  `${API_URL}/api/prospectos`,
                  {
                    headers: {
                      Authorization:
                        `Bearer ${token}`
                    }
                  }
                ),

                fetch(
                  `${API_URL}/api/empleados`,
                  {
                    headers: {
                      Authorization:
                        `Bearer ${token}`
                    }
                  }
                )
              ]);

            let listaProspectos = [];

            if (
              respuestaProspectos.status ===
                "fulfilled" &&
              respuestaProspectos.value.ok
            ) {
              const data =
                await respuestaProspectos
                  .value
                  .json();

              listaProspectos =
                Array.isArray(data)
                  ? data
                  : Array.isArray(
                      data?.prospectos
                    )
                  ? data.prospectos
                  : Array.isArray(
                      data?.data
                    )
                  ? data.data
                  : [];
            }

            const listaActivos =
              listaProspectos.filter(
                prospecto => {
                  const estatus =
                    String(
                      prospecto.estatus ||
                      prospecto.estado ||
                      ""
                    )
                      .trim()
                      .toLowerCase();

                  return ![
                    "contratado",
                    "no_contratado"
                  ].includes(
                    estatus
                  );
                }
              );

            let listaEmpleados = [];

            if (
              respuestaEmpleados.status ===
                "fulfilled" &&
              respuestaEmpleados.value.ok
            ) {
              const data =
                await respuestaEmpleados
                  .value
                  .json();

              listaEmpleados =
                Array.isArray(data)
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

            console.log(
              "📊 Dashboard RH:",
              {
                prospectos:
                  listaProspectos.length,

                prospectosActivos:
                  listaActivos.length,

                empleados:
                  listaEmpleados.length
              }
            );

            setStats(
              prev => ({
                ...prev,

                prospectos:
                  listaProspectos.length,

                prospectosActivos:
                  listaActivos.length,

                empleados:
                  listaEmpleados.length
              })
            );
          }

        } catch (err) {
          console.warn(
            "⚠️ Error cargando información del Dashboard:",
            err
          );

        } finally {
          setStatsLoading(false);
        }
      };

    cargarDatos();

  }, [
    esPsicologo,
    esUsuarioRH
  ]);

  const userKey =
    user?.id_usuario ||
    user?.id ||
    user?.correo ||
    rol ||
    "usuario";

  const tutorialKey =
    `mirrorsoul_dashboard_tutorial_${userKey}`;

  const [
    mostrarTutorial,
    setMostrarTutorial
  ] = useState(false);

  useEffect(() => {
    const visitas =
      Number(
        localStorage.getItem(
          tutorialKey
        ) || 0
      );

    if (visitas < 2) {
      setMostrarTutorial(true);
    }

    localStorage.setItem(
      tutorialKey,
      String(visitas + 1)
    );

  }, [
    tutorialKey
  ]);

  const [
    ayuda,
    setAyuda
  ] = useState(null);

  const cerrarAyudas = () => {
    setMostrarTutorial(false);
    setAyuda(null);
  };

  const obtenerTutorial = () => {
    if (esPsicologo) {
      return {
        titulo:
          "¿Cómo usar tu Dashboard clínico?",

        descripcion:
          "Estas son las tres opciones principales para comenzar. El trabajo clínico detallado se realiza dentro del expediente de cada paciente.",

        pasos: [
          {
            icon: "➕",
            titulo:
              "Registrar paciente",
            texto:
              "Aquí registras por primera vez los datos básicos del paciente. Al guardar, MirrorSoul crea su expediente clínico y su identificador."
          },

          {
            icon: "👥",
            titulo:
              "Ver pacientes",
            texto:
              "Aquí aparecen todos los pacientes que has registrado. Abre un expediente para continuar con su proceso clínico."
          },

          {
            icon: "📅",
            titulo:
              "Citas",
            texto:
              "Aquí puedes consultar, organizar y administrar las citas de tus pacientes."
          }
        ]
      };
    }

    if (esUsuarioRH) {
      return {
        titulo:
          "¿Cómo usar tu Dashboard de RH?",

        descripcion:
          "Desde aquí inicias y administras los procesos de selección.",

        pasos: [
          {
            icon: "➕",
            titulo:
              "Registrar prospecto",
            texto:
              "Aquí registras a una persona que inicia un proceso de selección."
          },

          {
            icon: "👥",
            titulo:
              "Ver prospectos",
            texto:
              "Aquí consultas los expedientes de selección y continúas con entrevistas, pruebas y seguimiento."
          },

          {
            icon: "👔",
            titulo:
              "Ver empleados",
            texto:
              "Aquí aparecen las personas que ya fueron convertidas en empleados."
          },

          {
            icon: "📅",
            titulo:
              "Calendario",
            texto:
              "Aquí administras entrevistas, citas y actividades del área de Recursos Humanos."
          }
        ]
      };
    }

    if (esMaster) {
      return {
        titulo:
          "¿Cómo usar el Dashboard Master?",

        descripcion:
          "Desde aquí administras la estructura general de MirrorSoul.",

        pasos: [
          {
            icon: "🛡️",
            titulo:
              "Administradores",
            texto:
              "Registra administradores responsables de cada área."
          },

          {
            icon: "🧠",
            titulo:
              "Psicólogos",
            texto:
              "Registra y consulta psicólogos del sistema."
          },

          {
            icon: "💼",
            titulo:
              "Recursos Humanos",
            texto:
              "Administra usuarios del área de RH."
          },

          {
            icon: "🎓",
            titulo:
              "Educativo",
            texto:
              "Administra usuarios del área educativa."
          }
        ]
      };
    }

    if (esAdminNormal) {
      return {
        titulo:
          "¿Cómo usar esta pantalla?",

        descripcion:
          "Desde aquí puedes registrar y consultar los usuarios correspondientes a tu área.",

        pasos: [
          {
            icon: "➕",
            titulo:
              "Registrar usuario",
            texto:
              "Utiliza esta opción para agregar nuevos integrantes a tu equipo."
          },

          {
            icon: "👥",
            titulo:
              "Consultar usuarios",
            texto:
              "Aquí puedes revisar los usuarios que has registrado."
          }
        ]
      };
    }

    if (
      esUsuarioEducativo
    ) {
      return {
        titulo:
          "¿Cómo usar tu área educativa?",

        descripcion:
          "Desde aquí accedes a las herramientas correspondientes al área educativa.",

        pasos: [
          {
            icon: "🎓",
            titulo:
              "Mi área educativa",
            texto:
              "Ingresa aquí para comenzar a utilizar las herramientas educativas disponibles."
          }
        ]
      };
    }

    return {
      titulo:
        "¿Cómo usar esta pantalla?",

      descripcion:
        "Selecciona una opción para comenzar.",

      pasos: [
        {
          icon: "👤",
          titulo:
            "Mi área",
          texto:
            "Desde aquí puedes acceder a las herramientas disponibles para tu cuenta."
        }
      ]
    };
  };

  const tutorial =
    obtenerTutorial();

  const obtenerWorkflow =
    () => {

      if (esPsicologo) {
        const tienePacientes =
          stats.pacientes > 0;

        return {
          title:
            "Ruta de inicio",

          description:
            "Sigue estos pasos para comenzar y organizar tu trabajo clínico.",

          steps: [
            {
              id:
                "registro",

              icon:
                "👤",

              title:
                "Registrar paciente",

              description:
                "Crea el expediente clínico del paciente.",

              status:
                tienePacientes
                  ? "completed"
                  : "current",

              action:
                "registrarPaciente"
            },

            {
              id:
                "pacientes",

              icon:
                "📁",

              title:
                "Ver pacientes",

              description:
                "Consulta y administra los expedientes clínicos.",

              status:
                tienePacientes
                  ? "current"
                  : "pending",

              action:
                "pacientes"
            },

            {
              id:
                "citas",

              icon:
                "📅",

              title:
                "Citas",

              description:
                "Consulta y organiza las citas de tus pacientes.",

              status:
                tienePacientes
                  ? "current"
                  : "pending",

              action:
                "citas"
            }
          ]
        };
      }

      if (esUsuarioRH) {
        const tieneProspectos =
          stats.prospectos > 0;

        const tieneProspectosActivos =
          stats.prospectosActivos > 0;

        const tieneEmpleados =
          stats.empleados > 0;

        return {
          title:
            "Ruta del proceso de selección",

          description:
            "Sigue las etapas principales para organizar el proceso del prospecto.",

          steps: [
            {
              id:
                "registro",

              icon:
                "👤",

              title:
                "Registrar prospecto",

              description:
                "Registra a la persona candidata.",

              status:
                tieneProspectos ||
                tieneEmpleados
                  ? "completed"
                  : "current",

              route:
                "/registrar-prospecto"
            },

            {
              id:
                "expediente",

              icon:
                "📁",

              title:
                "Ver prospectos",

              description:
                "Abre y administra los expedientes.",

              status:
                tieneProspectos ||
                tieneEmpleados
                  ? "completed"
                  : "pending",

              route:
                "/prospectos"
            },

            {
              id:
                "evaluacion",

              icon:
                "🧪",

              title:
                "Evaluación",

              description:
                "Continúa con entrevistas, pruebas y seguimiento.",

              status:
                tieneProspectosActivos
                  ? "current"
                  : tieneEmpleados ||
                    tieneProspectos
                  ? "completed"
                  : "pending",

              route:
                "/prospectos"
            },

            {
              id:
                "empleados",

              icon:
                "👔",

              title:
                "Empleados",

              description:
                "Consulta las personas incorporadas.",

              status:
                tieneEmpleados
                  ? "completed"
                  : "pending",

              route:
                "/empleados"
            }
          ]
        };
      }

      if (
        esAdminNormal &&
        area === "clinica"
      ) {
        return {
          title:
            "Ruta administrativa clínica",

          description:
            "Registra y administra a los psicólogos de tu equipo.",

          steps: [
            {
              id:
                "registro",

              icon:
                "➕",

              title:
                "Registrar psicólogo",

              description:
                "Agrega un psicólogo a tu equipo.",

              status:
                "current",

              action:
                "registerPsychologist"
            },

            {
              id:
                "consulta",

              icon:
                "👥",

              title:
                "Ver psicólogos",

              description:
                "Consulta los psicólogos registrados.",

              status:
                "pending",

              action:
                "psychologistView"
            }
          ]
        };
      }

      if (
        esAdminNormal &&
        area === "rh"
      ) {
        return {
          title:
            "Ruta administrativa RH",

          description:
            "Registra y administra usuarios de Recursos Humanos.",

          steps: [
            {
              id:
                "registro",

              icon:
                "➕",

              title:
                "Registrar usuario RH",

              description:
                "Agrega un nuevo integrante de RH.",

              status:
                "current",

              action:
                "registerUsuarioRH"
            },

            {
              id:
                "consulta",

              icon:
                "👥",

              title:
                "Ver usuarios RH",

              description:
                "Consulta tu equipo de Recursos Humanos.",

              status:
                "pending",

              action:
                "usuariosRH"
            }
          ]
        };
      }

      if (
        esAdminNormal &&
        area === "educativo"
      ) {
        return {
          title:
            "Ruta administrativa educativa",

          description:
            "Registra y administra usuarios de tu área educativa.",

          steps: [
            {
              id:
                "registro",

              icon:
                "➕",

              title:
                "Registrar usuario",

              description:
                "Agrega un usuario educativo.",

              status:
                "current",

              action:
                "registerUsuarioEducativo"
            },

            {
              id:
                "consulta",

              icon:
                "🎓",

              title:
                "Ver usuarios",

              description:
                "Consulta los usuarios registrados.",

              status:
                "pending",

              action:
                "usuariosEducativo"
            }
          ]
        };
      }

      if (
        esAdminNormal &&
        area === "independiente"
      ) {
        return {
          title:
            "Ruta administrativa",

          description:
            "Registra y administra usuarios de tu equipo.",

          steps: [
            {
              id:
                "registro",

              icon:
                "➕",

              title:
                "Registrar usuario",

              description:
                "Agrega un nuevo usuario.",

              status:
                "current",

              action:
                "registerUsuarioIndependiente"
            },

            {
              id:
                "consulta",

              icon:
                "👤",

              title:
                "Ver usuarios",

              description:
                "Consulta los usuarios registrados.",

              status:
                "pending",

              action:
                "usuariosIndependiente"
            }
          ]
        };
      }

      return null;
    };

  const workflow =
    obtenerWorkflow();

  const irPasoWorkflow =
    step => {
      if (!step) {
        return;
      }

      if (step.route) {
        navigate(
          step.route
        );

        return;
      }

      if (
        step.action &&
        onNavigate
      ) {
        onNavigate(
          step.action
        );
      }
    };

  const obtenerMensajesAvatar =
    () => {
      const mensajes = [];

      if (statsLoading) {
        return [
          "🔄 Estoy revisando tu información y pendientes..."
        ];
      }

      if (esPsicologo) {
        if (
          stats.pacientes === 0
        ) {
          mensajes.push(
            "👤 Aún no tienes pacientes registrados. Puedes comenzar creando tu primer expediente."
          );

          mensajes.push(
            "📋 Recuerda que primero debes registrar al paciente para comenzar su proceso clínico."
          );

        } else {
          mensajes.push(
            `👥 Tienes ${stats.pacientes} paciente${
              stats.pacientes === 1
                ? ""
                : "s"
            } registrado${
              stats.pacientes === 1
                ? ""
                : "s"
            }.`
          );

          mensajes.push(
            "📁 Abre el expediente del paciente para continuar con su trabajo clínico."
          );
        }

        if (
          stats.citas > 0
        ) {
          mensajes.push(
            `📅 Tienes ${stats.citas} cita${
              stats.citas === 1
                ? ""
                : "s"
            } programada${
              stats.citas === 1
                ? ""
                : "s"
            }.`
          );
        }

        if (
          stats.proximaCita
        ) {
          mensajes.push(
            `⏰ Tu próxima cita es ${stats.proximaCita}.`
          );
        }

        if (
          stats.sesionesAbiertas >
          0
        ) {
          mensajes.push(
            `🩺 Tienes ${stats.sesionesAbiertas} sesión${
              stats.sesionesAbiertas === 1
                ? ""
                : "es"
            } activa${
              stats.sesionesAbiertas === 1
                ? ""
                : "s"
            } sin finalizar.`
          );
        }

        if (
          stats.seguimientosPendientes >
          0
        ) {
          mensajes.push(
            `📋 Tienes ${stats.seguimientosPendientes} seguimiento${
              stats.seguimientosPendientes === 1
                ? ""
                : "s"
            } pendiente${
              stats.seguimientosPendientes === 1
                ? ""
                : "s"
            }.`
          );
        }

        if (
          stats.pruebasPendientes >
          0
        ) {
          mensajes.push(
            `🧪 Tienes ${stats.pruebasPendientes} prueba${
              stats.pruebasPendientes === 1
                ? ""
                : "s"
            } pendiente${
              stats.pruebasPendientes === 1
                ? ""
                : "s"
            } de revisar.`
          );
        }

        if (
          stats.preanalisisPendientes >
          0
        ) {
          mensajes.push(
            `🧠 Tienes ${stats.preanalisisPendientes} Preanálisis IA pendiente${
              stats.preanalisisPendientes === 1
                ? ""
                : "s"
            } de revisar.`
          );
        }

        mensajes.push(
          "🩺 La sesión es el centro del trabajo clínico en MirrorSoul."
        );

        mensajes.push(
          "🧠 MirrorSoul genera un Preanálisis IA como apoyo; no sustituye el criterio profesional."
        );

        mensajes.push(
          "⚕️ El diagnóstico clínico final corresponde al psicólogo."
        );

        mensajes.push(
          "⚠️ El resultado de una prueba psicológica por sí solo no establece un diagnóstico."
        );

        mensajes.push(
          "🔎 Revisa siempre el Preanálisis IA antes de finalizar una sesión."
        );

        mensajes.push(
          "🧪 Las pruebas deben interpretarse junto con entrevista, historial, observaciones y evolución clínica."
        );

        mensajes.push(
          "🎙️ El audio presencial es opcional y puede utilizarse como apoyo cuando sea necesario."
        );

        mensajes.push(
          "📞 La videollamada puede utilizarse cuando la consulta se realiza a distancia."
        );

        mensajes.push(
          "📅 Después de finalizar una sesión puedes decidir si es necesario programar una próxima cita."
        );
      }

      if (esUsuarioRH) {
        if (
          stats.prospectos === 0
        ) {
          mensajes.push(
            "👤 Aún no tienes prospectos registrados. Registra uno para comenzar un proceso de selección."
          );

          mensajes.push(
            "📋 Primero registra al prospecto para crear su expediente de selección."
          );

        } else {
          mensajes.push(
            `💼 Tienes ${stats.prospectos} prospecto${
              stats.prospectos === 1
                ? ""
                : "s"
            } registrado${
              stats.prospectos === 1
                ? ""
                : "s"
            }.`
          );

          mensajes.push(
            "📁 Abre un expediente para continuar con entrevistas, pruebas, observaciones y seguimiento."
          );
        }

        if (
          stats.empleados > 0
        ) {
          mensajes.push(
            `👔 Tienes ${stats.empleados} empleado${
              stats.empleados === 1
                ? ""
                : "s"
            } incorporado${
              stats.empleados === 1
                ? ""
                : "s"
            }.`
          );
        }

        mensajes.push(
          "🧪 Las pruebas psicométricas apoyan el proceso de selección; no sustituyen la valoración profesional."
        );

        mensajes.push(
          "👔 Cuando el proceso finalice puedes convertir al prospecto en empleado."
        );
      }

      if (
        mensajes.length === 0
      ) {
        mensajes.push(
          "😊 Selecciona una opción para continuar con tu trabajo."
        );

        mensajes.push(
          "❓ Si necesitas orientación, utiliza el botón «¿Cómo usar esta pantalla?»."
        );
      }

      return mensajes;
    };

  const mensajesAvatar =
    obtenerMensajesAvatar();

  return (
    <div style={page}>
      <main style={mainContent}>

        <div
          style={decorCircleOne}
        />

        <div
          style={decorCircleTwo}
        />

        <div
          style={decorCircleThree}
        />

        <section
          style={welcomeSection}
        >
          <div
            style={welcomeText}
          >
            <h1 style={title}>
              ¡Hola,{" "}

              <span
                style={name}
                onMouseEnter={
                  handleHoverEmoji
                }
              >
                {user?.nombre ||
                  "Usuario"}
              </span>

              !{" "}

              <span>
                {emoji}
              </span>
            </h1>

            <p style={subtitle}>
              🌱 Selecciona una opción para continuar
              <br />
              con tu trabajo.
            </p>

            <button
              type="button"
              style={helpButton}
              onClick={() => {
                setAyuda(null);

                setMostrarTutorial(
                  true
                );
              }}
            >
              ❓ ¿Cómo usar esta pantalla?
            </button>
          </div>

          <div
            style={
              avatarContainer
            }
          >
            <Avatar
              mensajesContextuales={
                mensajesAvatar
              }
            />
          </div>
        </section>

        {workflow && (
          <WorkflowGuide
            title={
              workflow.title
            }

            description={
              workflow.description
            }

            steps={
              workflow.steps
            }

            onStepClick={
              irPasoWorkflow
            }
          />
        )}

        <section
          style={cardsContainer}
        >

          {esMaster && (
            <>
              <DashboardCard
                icon="➕"
                title="Registrar psicólogo"
                description="Añade un nuevo psicólogo al sistema"
                accent="purple"
                help="Aquí registras a un nuevo psicólogo para que pueda acceder al área clínica."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "registerPsychologist"
                  )
                }
              />

              <DashboardCard
                icon="👥"
                title="Ver psicólogos"
                description="Consulta y gestiona todos los psicólogos"
                accent="blue"
                help="Aquí aparecen los psicólogos registrados en el sistema."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "psychologistView"
                  )
                }
              />

              <DashboardCard
                icon="🛡️"
                title="Registrar administrador"
                description="Crea administradores para las diferentes áreas"
                accent="green"
                help="Aquí puedes crear administradores y asignarlos a Clínica, RH, Educativo u otra área."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "registerAdmin"
                  )
                }
              />

              <DashboardCard
                icon="➕"
                title="Registrar usuario RH"
                description="Añade usuarios al área de Recursos Humanos"
                accent="purple"
                help="Aquí registras usuarios que trabajarán dentro del módulo de Recursos Humanos."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "registerUsuarioRH"
                  )
                }
              />

              <DashboardCard
                icon="👥"
                title="Ver usuarios RH"
                description="Consulta los usuarios del área de Recursos Humanos"
                accent="blue"
                help="Aquí puedes consultar los usuarios registrados en Recursos Humanos."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "usuariosRH"
                  )
                }
              />

              <DashboardCard
                icon="➕"
                title="Registrar usuario educativo"
                description="Añade usuarios al área educativa"
                accent="purple"
                help="Aquí agregas usuarios del área educativa."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "registerUsuarioEducativo"
                  )
                }
              />

              <DashboardCard
                icon="🎓"
                title="Ver usuarios educativos"
                description="Consulta los usuarios del área educativa"
                accent="blue"
                help="Aquí aparecen los usuarios registrados en el área educativa."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "usuariosEducativo"
                  )
                }
              />

              <DashboardCard
                icon="➕"
                title="Registrar usuario independiente"
                description="Añade usuarios al área independiente"
                accent="purple"
                help="Aquí puedes registrar usuarios independientes."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "registerUsuarioIndependiente"
                  )
                }
              />

              <DashboardCard
                icon="👤"
                title="Ver usuarios independientes"
                description="Consulta los usuarios del área independiente"
                accent="blue"
                help="Aquí aparecen los usuarios independientes registrados."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "usuariosIndependiente"
                  )
                }
              />
            </>
          )}

          {esAdminNormal &&
            area ===
              "clinica" && (
              <>
                <DashboardCard
                  icon="➕"
                  title="Registrar psicólogo"
                  description="Añade un nuevo psicólogo a tu equipo"
                  accent="purple"
                  help="Aquí registras a los psicólogos que formarán parte de tu equipo."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "registerPsychologist"
                    )
                  }
                />

                <DashboardCard
                  icon="👥"
                  title="Ver psicólogos"
                  description="Consulta únicamente los psicólogos que tú registraste"
                  accent="blue"
                  help="Aquí puedes consultar los psicólogos registrados por tu cuenta."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "psychologistView"
                    )
                  }
                />
              </>
            )}

          {esAdminNormal &&
            area === "rh" && (
              <>
                <DashboardCard
                  icon="➕"
                  title="Registrar usuario RH"
                  description="Añade un nuevo usuario a tu equipo de RH"
                  accent="purple"
                  help="Aquí agregas usuarios que trabajarán contigo en Recursos Humanos."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "registerUsuarioRH"
                    )
                  }
                />

                <DashboardCard
                  icon="👥"
                  title="Ver usuarios RH"
                  description="Consulta únicamente los usuarios RH que tú registraste"
                  accent="blue"
                  help="Aquí puedes consultar los integrantes de tu equipo de Recursos Humanos."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "usuariosRH"
                    )
                  }
                />
              </>
            )}

          {esAdminNormal &&
            area ===
              "educativo" && (
              <>
                <DashboardCard
                  icon="➕"
                  title="Registrar usuario educativo"
                  description="Añade un nuevo usuario a tu equipo educativo"
                  accent="purple"
                  help="Aquí registras integrantes de tu equipo educativo."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "registerUsuarioEducativo"
                    )
                  }
                />

                <DashboardCard
                  icon="🎓"
                  title="Ver usuarios educativos"
                  description="Consulta únicamente los usuarios educativos que tú registraste"
                  accent="blue"
                  help="Aquí aparecen los usuarios educativos registrados por ti."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "usuariosEducativo"
                    )
                  }
                />
              </>
            )}

          {esAdminNormal &&
            area ===
              "independiente" && (
              <>
                <DashboardCard
                  icon="➕"
                  title="Registrar usuario"
                  description="Añade un nuevo usuario a tu equipo"
                  accent="purple"
                  help="Aquí puedes registrar un nuevo usuario."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "registerUsuarioIndependiente"
                    )
                  }
                />

                <DashboardCard
                  icon="👤"
                  title="Ver usuarios"
                  description="Consulta únicamente los usuarios que tú registraste"
                  accent="blue"
                  help="Aquí aparecen los usuarios que has registrado."
                  onHelp={
                    setAyuda
                  }
                  onClick={() =>
                    onNavigate(
                      "usuariosIndependiente"
                    )
                  }
                />
              </>
            )}

          {esPsicologo && (
            <>
              <DashboardCard
                icon="➕"
                title="Registrar paciente"
                description="Añade un nuevo paciente al sistema"
                accent="purple"
                help="Aquí registras por primera vez los datos básicos de un paciente. Al guardar, se crea su expediente clínico y su ID MirrorSoul."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "registrarPaciente"
                  )
                }
              />

              <DashboardCard
                icon="👥"
                title={
                  <>
                    Ver pacientes
                    <br />

                    <span
                      style={{
                        fontSize:
                          "15px"
                      }}
                    >
                      (expedientes clínicos)
                    </span>
                  </>
                }
                description="Consulta y gestiona tus expedientes clínicos"
                accent="blue"
                help="Aquí aparecen tus pacientes registrados. Abre un expediente para trabajar con historial clínico, seguimiento, sesiones, pruebas psicológicas y Preanálisis IA."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "pacientes"
                  )
                }
              />

              <DashboardCard
                icon="📅"
                title="Citas"
                description="Gestiona citas y agendamientos"
                accent="green"
                help="Aquí puedes consultar, organizar y administrar las citas de tus pacientes."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "citas"
                  )
                }
              />
            </>
          )}

          {esUsuarioRH && (
            <>
              <DashboardCard
                icon="➕"
                title="Registrar prospecto"
                description="Registra una persona que está en proceso de selección"
                accent="purple"
                help="Aquí registras a una persona que inicia un proceso de selección."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  navigate(
                    "/registrar-prospecto"
                  )
                }
              />

              <DashboardCard
                icon="👥"
                title="Ver prospectos"
                description="Consulta y gestiona los expedientes de las personas en proceso de selección"
                accent="blue"
                help="Aquí aparecen los prospectos registrados. Abre un expediente para gestionar entrevistas, pruebas, seguimiento, documentos, observaciones y reportes."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  navigate(
                    "/prospectos"
                  )
                }
              />

              <DashboardCard
                icon="👔"
                title="Ver empleados"
                description="Consulta y gestiona los expedientes de los empleados"
                accent="green"
                help="Aquí aparecen las personas que ya fueron convertidas en empleados."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  navigate(
                    "/empleados"
                  )
                }
              />

              <DashboardCard
                icon="📅"
                title="Calendario"
                description="Gestiona entrevistas, citas y actividades del área de RH"
                accent="green"
                help="Aquí puedes consultar y organizar entrevistas, citas y otras actividades del proceso de selección."
                onHelp={
                  setAyuda
                }
                onClick={() =>
                  onNavigate(
                    "citasRH"
                  )
                }
              />
            </>
          )}

          {esUsuarioEducativo && (
            <DashboardCard
              icon="🎓"
              title="Mi área educativa"
              description="Accede a las herramientas disponibles para tu trabajo"
              accent="blue"
              help="Desde aquí puedes acceder a las herramientas correspondientes al área educativa."
              onHelp={
                setAyuda
              }
              onClick={() =>
                onNavigate(
                  "usuariosEducativo"
                )
              }
            />
          )}

          {esUsuarioIndependiente && (
            <DashboardCard
              icon="👤"
              title="Mi área independiente"
              description="Accede a las herramientas disponibles para tu trabajo"
              accent="blue"
              help="Desde aquí puedes acceder a las herramientas disponibles para tu cuenta."
              onHelp={
                setAyuda
              }
              onClick={() =>
                onNavigate(
                  "usuariosIndependiente"
                )
              }
            />
          )}

        </section>

        <footer style={footer}>
          © 2026{" "}

          <span
            style={footerBrand}
          >
            MirrorSoul
          </span>

          . Todos los derechos reservados.
        </footer>

        {mostrarTutorial && (
          <div
            style={overlay}
            onClick={
              cerrarAyudas
            }
          >
            <div
              style={
                tutorialModal
              }
              onClick={e =>
                e.stopPropagation()
              }
            >
              <button
                type="button"
                style={
                  closeButton
                }
                onClick={
                  cerrarAyudas
                }
              >
                ×
              </button>

              <div
                style={
                  tutorialIcon
                }
              >
                🧭
              </div>

              <h2
                style={
                  tutorialTitle
                }
              >
                {tutorial.titulo}
              </h2>

              <p
                style={
                  tutorialDescription
                }
              >
                {
                  tutorial.descripcion
                }
              </p>

              <div
                style={
                  tutorialSteps
                }
              >
                {tutorial.pasos.map(
                  (
                    paso,
                    index
                  ) => (
                    <div
                      key={
                        `${paso.titulo}-${index}`
                      }
                      style={
                        tutorialStep
                      }
                    >
                      <div
                        style={
                          stepNumber
                        }
                      >
                        {index + 1}
                      </div>

                      <div
                        style={
                          stepIcon
                        }
                      >
                        {paso.icon}
                      </div>

                      <div>
                        <div
                          style={
                            stepTitle
                          }
                        >
                          {
                            paso.titulo
                          }
                        </div>

                        <div
                          style={
                            stepText
                          }
                        >
                          {
                            paso.texto
                          }
                        </div>
                      </div>
                    </div>
                  )
                )}
              </div>

              <div
                style={
                  tutorialNotice
                }
              >
                💡 Esta guía se muestra automáticamente solo las primeras dos veces. Después puedes abrirla cuando quieras desde{" "}

                <strong>
                  ❓ ¿Cómo usar esta pantalla?
                </strong>
              </div>

              <button
                type="button"
                style={
                  understoodButton
                }
                onClick={() =>
                  setMostrarTutorial(
                    false
                  )
                }
              >
                Entendido ✓
              </button>
            </div>
          </div>
        )}

      </main>
    </div>
  );
};

const DashboardCard = ({
  icon,
  title,
  description,
  accent,
  onClick,
  help
}) => {

  const [
    mostrarAyuda,
    setMostrarAyuda
  ] = useState(false);

  const accentColors = {
    purple: {
      border:
        "#8B4DE8",

      iconBackground:
        "#F3E9FF",

      iconColor:
        "#7B3FE4",

      title:
        "#7540D5"
    },

    blue: {
      border:
        "#4A7FF5",

      iconBackground:
        "#EAF1FF",

      iconColor:
        "#2167DD",

      title:
        "#2167DD"
    },

    green: {
      border:
        "#54C96B",

      iconBackground:
        "#ECF9EF",

      iconColor:
        "#3BAE55",

      title:
        "#3BAE55"
    }
  };

  const colors =
    accentColors[accent] ||
    accentColors.blue;

  const tituloAyuda =
    typeof title === "string"
      ? title
      : "Ayuda";

  const alternarAyuda =
    e => {
      e.preventDefault();
      e.stopPropagation();

      setMostrarAyuda(
        actual =>
          !actual
      );
    };

  return (
    <button
      type="button"

      style={{
        ...card,

        borderBottom:
          `4px solid ${colors.border}`,

        zIndex:
          mostrarAyuda
            ? 25
            : 1
      }}

      onClick={
        onClick
      }

      onMouseEnter={e => {
        e.currentTarget.style.transform =
          "translateY(-6px)";

        e.currentTarget.style.boxShadow =
          "0 15px 30px rgba(40,80,140,.14)";
      }}

      onMouseLeave={e => {
        e.currentTarget.style.transform =
          "translateY(0)";

        e.currentTarget.style.boxShadow =
          "0 8px 20px rgba(40,80,140,.08)";
      }}
    >

      {help && (
        <span
          role="button"
          tabIndex={0}
          title="¿Para qué sirve?"

          style={{
            ...cardHelpButton,

            ...(mostrarAyuda
              ? cardHelpButtonActive
              : {})
          }}

          onClick={
            alternarAyuda
          }

          onKeyDown={e => {
            if (
              e.key ===
                "Enter" ||
              e.key === " "
            ) {
              alternarAyuda(
                e
              );
            }
          }}
        >
          ?
        </span>
      )}

      {help &&
        mostrarAyuda && (
          <div
            style={
              helpPopover
            }

            onClick={e => {
              e.preventDefault();
              e.stopPropagation();
            }}
          >

            <div
              style={
                helpPopoverArrow
              }
            />

            <div
              style={
                helpPopoverHeader
              }
            >

              <span
                style={
                  helpPopoverIcon
                }
              >
                ❓
              </span>

              <strong
                style={
                  helpPopoverTitle
                }
              >
                {tituloAyuda}
              </strong>

              <span
                role="button"
                tabIndex={0}
                title="Cerrar"

                style={
                  helpPopoverClose
                }

                onClick={
                  alternarAyuda
                }

                onKeyDown={e => {
                  if (
                    e.key ===
                      "Enter" ||
                    e.key === " "
                  ) {
                    alternarAyuda(
                      e
                    );
                  }
                }}
              >
                ×
              </span>

            </div>

            <p
              style={
                helpPopoverText
              }
            >
              {help}
            </p>

          </div>
        )}

      <div
        style={{
          ...cardIcon,

          background:
            colors.iconBackground,

          color:
            colors.iconColor
        }}
      >
        {icon}
      </div>

      <div
        style={{
          ...cardTitle,

          color:
            colors.title
        }}
      >
        {title}
      </div>

      <div
        style={
          cardDescription
        }
      >
        {description}
      </div>

    </button>
  );
};

const page = {
  minHeight: "100%",
  width: "100%",
  background: "#F4F9FE",

  fontFamily:
    "'Segoe UI', Arial, sans-serif",

  color: "#1A2B4B",
  overflow: "hidden"
};

const mainContent = {
  minHeight:
    "calc(100vh - 86px)",

  position: "relative",

  padding:
    "55px 7%",

  boxSizing:
    "border-box",

  overflow:
    "hidden"
};

const decorCircleOne = {
  position: "absolute",

  width: "350px",
  height: "350px",

  borderRadius: "50%",

  background:
    "rgba(100,170,255,.08)",

  right: "-130px",
  bottom: "-150px",

  pointerEvents:
    "none"
};

const decorCircleTwo = {
  position: "absolute",

  width: "150px",
  height: "150px",

  borderRadius: "50%",

  background:
    "rgba(100,170,255,.08)",

  right: "20px",
  top: "80px",

  pointerEvents:
    "none"
};

const decorCircleThree = {
  position: "absolute",

  width: "10px",
  height: "10px",

  borderRadius: "50%",

  background:
    "rgba(60,120,220,.20)",

  right: "150px",
  top: "100px",

  boxShadow:
    "30px 20px 0 rgba(60,120,220,.15),60px -15px 0 rgba(60,120,220,.12)",

  pointerEvents:
    "none"
};

const welcomeSection = {
  maxWidth: "1150px",

  margin:
    "0 auto 32px",

  display: "flex",

  alignItems:
    "center",

  justifyContent:
    "space-between",

  position:
    "relative",

  zIndex: 2
};

const welcomeText = {
  flex: 1
};

const title = {
  margin:
    "0 0 12px",

  fontSize:
    "40px",

  fontWeight:
    "800",

  color:
    "#172B4D",

  letterSpacing:
    "-1px"
};

const name = {
  color:
    "#2167D5",

  cursor:
    "pointer"
};

const subtitle = {
  margin: 0,

  fontSize:
    "17px",

  lineHeight:
    "1.6",

  color:
    "#596B82"
};

const helpButton = {
  marginTop:
    "16px",

  border:
    "1px solid #C9DAF4",

  background:
    "#FFFFFF",

  color:
    "#2167D5",

  borderRadius:
    "999px",

  padding:
    "9px 15px",

  cursor:
    "pointer",

  fontSize:
    "12px",

  fontWeight:
    "800",

  boxShadow:
    "0 4px 12px rgba(40,80,140,.07)"
};

const avatarContainer = {
  width:
    "390px",

  minHeight:
    "170px",

  display:
    "flex",

  justifyContent:
    "center",

  alignItems:
    "center",

  background:
    "transparent",

  position:
    "relative",

  overflow:
    "visible",

  boxSizing:
    "border-box",

  transform:
    "translateY(-15px)"
};

const cardsContainer = {
  maxWidth:
    "1150px",

  margin:
    "0 auto",

  padding:
    "38px",

  background:
    "rgba(255,255,255,.90)",

  borderRadius:
    "20px",

  boxShadow:
    "0 8px 24px rgba(40,80,140,.08)",

  display:
    "grid",

  gridTemplateColumns:
    "repeat(3,1fr)",

  gap:
    "28px",

  position:
    "relative",

  zIndex: 3,

  boxSizing:
    "border-box"
};

const card = {
  minHeight:
    "245px",

  background:
    "#FFFFFF",

  border:
    "1px solid #E4EAF2",

  borderRadius:
    "16px",

  padding:
    "28px 22px 24px",

  cursor:
    "pointer",

  display:
    "flex",

  flexDirection:
    "column",

  justifyContent:
    "center",

  alignItems:
    "center",

  textAlign:
    "center",

  transition:
    "all .25s ease",

  boxShadow:
    "0 8px 20px rgba(40,80,140,.08)",

  fontFamily:
    "'Segoe UI', Arial, sans-serif",

  position:
    "relative"
};

const cardHelpButton = {
  position:
    "absolute",

  top:
    "12px",

  right:
    "12px",

  width:
    "27px",

  height:
    "27px",

  borderRadius:
    "50%",

  background:
    "#F1F6FD",

  border:
    "1px solid #D5E2F4",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  color:
    "#2167D5",

  fontWeight:
    "900",

  fontSize:
    "14px",

  cursor:
    "help",

  zIndex:
    5
};

const cardHelpButtonActive = {
  background:
    "#2167D5",

  color:
    "#FFFFFF",

  border:
    "1px solid #2167D5",

  boxShadow:
    "0 4px 12px rgba(33,103,213,.22)"
};

const helpPopover = {
  position:
    "absolute",

  top:
    "48px",

  right:
    "12px",

  width:
    "280px",

  maxWidth:
    "calc(100% - 24px)",

  padding:
    "15px 16px",

  background:
    "#FFFFFF",

  border:
    "1px solid #D7E3F3",

  borderRadius:
    "14px",

  boxShadow:
    "0 14px 34px rgba(30,60,100,.18)",

  zIndex:
    40,

  textAlign:
    "left",

  boxSizing:
    "border-box",

  cursor:
    "default"
};

const helpPopoverArrow = {
  position:
    "absolute",

  top:
    "-7px",

  right:
    "15px",

  width:
    "12px",

  height:
    "12px",

  background:
    "#FFFFFF",

  borderLeft:
    "1px solid #D7E3F3",

  borderTop:
    "1px solid #D7E3F3",

  transform:
    "rotate(45deg)"
};

const helpPopoverHeader = {
  display:
    "grid",

  gridTemplateColumns:
    "28px 1fr 26px",

  gap:
    "8px",

  alignItems:
    "center",

  marginBottom:
    "8px"
};

const helpPopoverIcon = {
  width:
    "28px",

  height:
    "28px",

  borderRadius:
    "8px",

  background:
    "#EEF4FF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "14px"
};

const helpPopoverTitle = {
  color:
    "#172B4D",

  fontSize:
    "14px",

  lineHeight:
    "1.3"
};

const helpPopoverClose = {
  width:
    "26px",

  height:
    "26px",

  borderRadius:
    "50%",

  background:
    "#F1F5F9",

  color:
    "#64748B",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontWeight:
    "800",

  fontSize:
    "18px",

  cursor:
    "pointer",

  lineHeight:
    1
};

const helpPopoverText = {
  margin:
    0,

  color:
    "#52657C",

  fontSize:
    "14px",

  lineHeight:
    "1.55",

  fontWeight:
    "500"
};

const cardIcon = {
  width:
    "64px",

  height:
    "64px",

  borderRadius:
    "50%",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "29px",

  marginBottom:
    "18px"
};

const cardTitle = {
  fontSize:
    "18px",

  fontWeight:
    "800",

  marginBottom:
    "12px",

  lineHeight:
    "1.3"
};

const cardDescription = {
  fontSize:
    "14px",

  lineHeight:
    "1.5",

  color:
    "#718096",

  maxWidth:
    "210px"
};

const footer = {
  maxWidth:
    "1150px",

  margin:
    "38px auto 0",

  paddingTop:
    "20px",

  borderTop:
    "1px solid #DCE5F0",

  textAlign:
    "center",

  fontSize:
    "12px",

  color:
    "#64748B",

  position:
    "relative",

  zIndex:
    2
};

const footerBrand = {
  color:
    "#2167D5",

  fontWeight:
    "700"
};

const overlay = {
  position:
    "fixed",

  inset:
    0,

  background:
    "rgba(18,35,61,.48)",

  display:
    "flex",

  justifyContent:
    "center",

  alignItems:
    "center",

  padding:
    "20px",

  zIndex:
    9999,

  backdropFilter:
    "blur(3px)"
};

const tutorialModal = {
  width:
    "100%",

  maxWidth:
    "700px",

  maxHeight:
    "88vh",

  overflowY:
    "auto",

  background:
    "#FFFFFF",

  borderRadius:
    "24px",

  padding:
    "30px",

  boxShadow:
    "0 24px 80px rgba(20,50,90,.25)",

  position:
    "relative",

  boxSizing:
    "border-box"
};

const closeButton = {
  position:
    "absolute",

  right:
    "16px",

  top:
    "13px",

  width:
    "34px",

  height:
    "34px",

  borderRadius:
    "50%",

  border:
    "none",

  background:
    "#F1F5F9",

  color:
    "#64748B",

  fontSize:
    "23px",

  cursor:
    "pointer",

  lineHeight:
    1
};

const tutorialIcon = {
  width:
    "58px",

  height:
    "58px",

  borderRadius:
    "16px",

  background:
    "#EAF1FF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "27px",

  marginBottom:
    "15px"
};

const tutorialTitle = {
  margin:
    "0 0 8px",

  color:
    "#172B4D",

  fontSize:
    "25px"
};

const tutorialDescription = {
  margin:
    "0 0 24px",

  color:
    "#667085",

  fontSize:
    "14px",

  lineHeight:
    "1.6"
};

const tutorialSteps = {
  display:
    "flex",

  flexDirection:
    "column",

  gap:
    "12px"
};

const tutorialStep = {
  display:
    "grid",

  gridTemplateColumns:
    "34px 48px 1fr",

  gap:
    "12px",

  alignItems:
    "center",

  padding:
    "14px",

  border:
    "1px solid #E5EBF3",

  borderRadius:
    "14px",

  background:
    "#FBFCFE"
};

const stepNumber = {
  width:
    "30px",

  height:
    "30px",

  borderRadius:
    "50%",

  background:
    "#2167D5",

  color:
    "#FFFFFF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontWeight:
    "900",

  fontSize:
    "12px"
};

const stepIcon = {
  width:
    "44px",

  height:
    "44px",

  borderRadius:
    "12px",

  background:
    "#EEF4FF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "22px"
};

const stepTitle = {
  fontSize:
    "14px",

  fontWeight:
    "900",

  color:
    "#344054",

  marginBottom:
    "3px"
};

const stepText = {
  fontSize:
    "12px",

  color:
    "#667085",

  lineHeight:
    "1.5"
};

const tutorialNotice = {
  marginTop:
    "20px",

  padding:
    "12px 14px",

  borderRadius:
    "12px",

  background:
    "#FFF9E8",

  border:
    "1px solid #F6D98B",

  color:
    "#7A5A10",

  fontSize:
    "11px",

  lineHeight:
    "1.5"
};

const understoodButton = {
  width:
    "100%",

  marginTop:
    "20px",

  border:
    "none",

  background:
    "linear-gradient(135deg,#2167D5,#5795F2)",

  color:
    "#FFFFFF",

  borderRadius:
    "12px",

  padding:
    "12px 18px",

  cursor:
    "pointer",

  fontWeight:
    "900",

  fontSize:
    "13px"
};

export default Dashboard;