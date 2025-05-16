import { createContext, useContext, useEffect, useState } from "react";

// Create a Context for the theme
const ViewContext = createContext();

// Custom hook to use the theme context
export const useView = () => useContext(ViewContext);

// Create a provider component
export const ViewProvider = ({ children }) => {
  const [isGridMode, setIsGridMode] = useState(false);

  // Load theme preference from localStorage or default to light mode
  useEffect(() => {
    const savedView = localStorage.getItem("view");
    if (savedView === "grid") {
      setIsGridMode(true);
    }
  }, []);

  // Toggle theme and store preference in localStorage
  const toggleView = () => {
    setIsGridMode((prevMode) => {
      const newMode = !prevMode;
      localStorage.setItem("view", newMode ? "grid" : "list");
      return newMode;
    });
  };

  return (
    <ViewContext.Provider value={{ isGridMode, toggleView }}>
      {children}
    </ViewContext.Provider>
  );
};
