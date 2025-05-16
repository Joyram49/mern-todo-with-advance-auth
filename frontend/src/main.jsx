import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { EditProvider } from "./context/EditContext.jsx";
import { ThemeProvider } from "./context/ThemeContext.jsx";
import { ViewProvider } from "./context/VIewContext.jsx";
import "./index.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <ThemeProvider>
      <ViewProvider>
        <EditProvider>
          <App />
        </EditProvider>
      </ViewProvider>
    </ThemeProvider>
  </StrictMode>
);
