import { ReactComponent as AddIcon } from "../../assets/add.svg";

function AddList() {
  return (
    <div className='w-full py-6 bg-secondaryBackground-foreground'>
      <div className='flex items-center gap-x-4 py-2 px-4'>
        <AddIcon className='w-6 h-6 stroke-icon-secondary ' />
        <p className='text-[15px] font-medium text-sidebar-text'>Add list</p>
      </div>
    </div>
  );
}

export default AddList;
