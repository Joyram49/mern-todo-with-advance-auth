import { ReactComponent as PlusIcon } from "../../assets/add.svg";
import { ReactComponent as CalenderIcon } from "../../assets/calendar.svg";
import { ReactComponent as NotifyIcon } from "../../assets/notifications.svg";
import { ReactComponent as RepeatIcon } from "../../assets/repeat.svg";
import { ReactComponent as StarIcon } from "../../assets/star.svg";
import TodoEditFooter from "./TodoEditFooter";

function TodoEdit() {
  return (
    <div className='w-full min-w-[452px] h-screen  bg-secondaryBackground py-10 stick top-10'>
      <div className='w-full h-full relative'>
        <div className='w-full flex flex-col justify-between  pl-12 mt-[32px] '>
          <div className='flex flex-col overflow-y-auto flex-grow'>
            <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
              <div className='w-full flex items-center justify-between px-5 py-6'>
                <form action='' className='flex gap-x-4 items-center'>
                  <input
                    id='data1'
                    type='checkbox'
                    className='appearance-none checked:appearance-auto checked:accent-text-primary w-[18px] h-[18px] rounded cursor-pointer border-2 border-text-primary'
                  />
                  <label
                    htmlFor='data1'
                    className=' text-text-primary text-[15px] '
                  >
                    Read a book
                  </label>
                </form>
                <div>
                  <StarIcon className='w-6 h-6 text-text-primary' />
                </div>
              </div>
            </div>
            <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
              <div className='w-full flex items-center justify-between px-5 py-3'>
                <div className='flex gap-x-4 items-center'>
                  <PlusIcon className='w-6 h-6 text-sidebar-text' />
                  <p className=' text-text-primary text-[15px] '>Add Step</p>
                </div>
              </div>
            </div>
            <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
              <div className='w-full flex items-center justify-between px-5 py-3'>
                <div className='flex gap-x-4 items-center'>
                  <NotifyIcon className='w-6 h-6 text-sidebar-text' />
                  <p className=' text-text-primary text-[15px] '>
                    Set Reminder
                  </p>
                </div>
              </div>
            </div>
            <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
              <div className='w-full flex items-center justify-between px-5 py-3'>
                <div className='flex gap-x-4 items-center'>
                  <CalenderIcon className='w-6 h-6 text-sidebar-text' />
                  <p className=' text-text-primary text-[15px] '>
                    Add Due Date
                  </p>
                </div>
              </div>
            </div>
            <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
              <div className='w-full flex items-center justify-between px-5 py-3'>
                <div className='flex gap-x-4 items-center'>
                  <RepeatIcon className='w-6 h-6 text-sidebar-text' />
                  <p className=' text-text-primary text-[15px] '>Repeat</p>
                </div>
              </div>
            </div>
            <div className='w-full border-t-[1.5px] border-[#496E4B33]'>
              <h1 className='text-side-text px-10 py-3'>Add Notes</h1>
            </div>
          </div>
          <div className='absolute bottom-0 left-0 w-full border-t-[1px] border-[#35793799] mb-32 '>
            <TodoEditFooter />
          </div>
        </div>
      </div>
    </div>
  );
}

export default TodoEdit;
