import { ReactComponent as CloseIcon } from "../../assets/close.svg";
import { ReactComponent as TrashIcon } from "../../assets/delete.svg";

function TodoEditFooter() {
  return (
    <div className='w-full flex justify-between items-center p-4'>
      <div>
        <CloseIcon className='w-6 h-6 text-text-primary' />
      </div>
      <div className='flex-1 text-center'>
        <p className='text-sidebar-text'>Selected Todo</p>
      </div>
      <div>
        <TrashIcon className='w-6 h-6 text-text-primary' />
      </div>
    </div>
  );
}

export default TodoEditFooter;
