import React, { createContext, useState, useContext } from "react";

const SelectedSpecialistContext = createContext();

export const SelectedSpecialistProvider = ({ children }) => {
  const [selectedSpecialist, setSelectedSpecialist] = useState(null);

  return (
    <SelectedSpecialistContext.Provider value={{ selectedSpecialist, setSelectedSpecialist }}>
      {children}
    </SelectedSpecialistContext.Provider>
  );
};

export const useSelectedSpecialist = () => useContext(SelectedSpecialistContext);

