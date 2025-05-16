import { ReactComponent as MoonIcon } from "../../assets/moon.svg";
import { ReactComponent as SunIcon } from "../../assets/sun.svg";

import { useTheme } from "../../context/ThemeContext";

const ThemeSwitcher = () => {
  const { isDarkMode, toggleTheme } = useTheme();

  return (
    <button onClick={toggleTheme} className='h-6 w-6 overflow-hidden'>
      {isDarkMode ? (
        <SunIcon className='w-full h-full text-icon-primary' />
      ) : (
        <MoonIcon className='w-full h-full text-icon-primary' />
      )}
    </button>
  );
};

export default ThemeSwitcher;
