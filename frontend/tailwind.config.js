/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        secondaryBackground: {
          DEFAULT: "var(--secondary-background)",
          foreground: "var(--secondary-foreground)",
        },
        text: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          success: "var(--text-success)",
        },
        sidebar: {
          text: "var(--sidebar-text)",
          textActive: "var(--sidebar-text-active)",
          bgActive: "var(--sidebar-bg-active)",
          darkBg: "var(--sidebar-dark-bg)",
          green: "var(--sidebar-green)",
        },
        button: {
          bg: "var(--button-bg)",
          text: "var(--button-text)",
        },
        icon: {
          primary: "var(--icon-primary)",
          secondary: "var(--icon-secondary)",
        },
        checkbox: {
          border: "var(--checkbox-border)",
          activeFill: "var(--checkbox-active-fill)",
        },
        todo: {
          text: "var(--todo-text)",
        },
        side: {
          text: "var(--side-text)",
        },
      },
      fontFamily: {
        sen: ["Sen", "serif"],
        outfit: ["Outfit", "serif"],
        inter: ["Inter", "serif"],
      },
    },
  },
  plugins: [],
};
