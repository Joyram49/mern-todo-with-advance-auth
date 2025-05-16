import { createContext, useContext, useState } from "react";

// Create a Context for the theme
const EditContext = createContext();

// Custom hook to use the theme context
export const useEdit = () => useContext(EditContext);

// Create a provider component
export const EditProvider = ({ children }) => {
  const [isEditMode, setIsEditMode] = useState(false);
  return (
    <EditContext.Provider value={{ isEditMode, setIsEditMode }}>
      {children}
    </EditContext.Provider>
  );
};
