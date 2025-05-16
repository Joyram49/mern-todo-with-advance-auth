import { ReactComponent as GridIcon } from "../../assets/Icon.svg";
import { ReactComponent as SearchIcon } from "../../assets/Icon2.svg";
import menuIcon from "../../assets/Icon3.svg";
import { ReactComponent as LogoutIcon } from "../../assets/log-out.svg";
import logoImg from "../../assets/logomark.svg";
import ThemeSwitcher from "./ThemSwitcher";

function Header() {
  return (
    <div className='w-full p-3 flex justify-between items-center border-b-[1.5px] border-background'>
      <div className='flex justify-start items-center gap-x-6'>
        <div className='block md:hidden'>
          <img src={menuIcon} alt='menu' className='h-6 w-6' />
        </div>
        <div className='flex'>
          <img src={logoImg} alt='logo' className='w-8 h-8' />
          <h1 className='font-sen font-[700] text-[24px] text-text-success'>
            DoIt
          </h1>
        </div>
      </div>
      <div className='flex-1 flex justify-end items-center gap-x-6'>
        <button
          className='w-6 h-6'
          onClick={() => {
            localStorage.removeItem("user");
            window.location.href = "/login";
          }}
        >
          <LogoutIcon className='text-icon-primary' />
        </button>

        <button className='w-6 h-6'>
          <SearchIcon className='text-icon-primary' />
        </button>
        <button className='w-6 h-6'>
          <GridIcon className='text-icon-primary' />
        </button>
        <ThemeSwitcher />
      </div>
    </div>
  );
}

export default Header;
