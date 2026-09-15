// src/main.jsx
import React from "react";
import ReactDOM from "react-dom/client";
import MainApp from "./MainApp.jsx";
import { PatientProvider } from "./components/PatientContext.jsx"; // 👈 Importa tu Provider
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    {/* 👇 Envolvemos toda la app en el Provider */}
    <PatientProvider>
      <MainApp />
    </PatientProvider>
  </React.StrictMode>
);
