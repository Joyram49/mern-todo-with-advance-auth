import { ReactComponent as CalenderIcon } from "../../assets/calendar.svg";
import { ReactComponent as CaretIcon } from "../../assets/caret-down.svg";
import { ReactComponent as NotifyIcon } from "../../assets/notifications.svg";
import { ReactComponent as RepeatIcon } from "../../assets/repeat.svg";

function AddTodo() {
  return (
    <div className='w-full flex flex-col'>
      <div className='flex items-center p-4'>
        <p className='font-outfit font-medium text-[13px] text-todo-text'>
          To Do
        </p>
        <CaretIcon className='w-6 h-6 text-todo-text' />
      </div>
      <div className='w-full flex flex-col gap-y-2 border-t-[1.5px] border-[#496E4B33] bg-custom-gradient py-4'>
        <div className='px-5 py-[42px] '>
          <h1 className='text-text-secondary'>Add A Task</h1>
        </div>
        <div className='w-full flex items-center justify-between px-5'>
          {/* icons here */}
          <div className='flex gap-x-4 items-center'>
            <NotifyIcon className='text-text-secondary' />
            <RepeatIcon className='text-text-secondary' />
            <CalenderIcon className='text-text-secondary' />
          </div>

          <button className='px-4 py-2 rounded-lg text-button-text font-medium bg-button-bg'>
            ADD TASK
          </button>
        </div>
      </div>
    </div>
  );
}

export default AddTodo;
