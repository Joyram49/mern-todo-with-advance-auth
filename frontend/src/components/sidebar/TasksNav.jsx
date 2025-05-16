import { ReactComponent as CalenderIcon } from "../../assets/calendar.svg";
import { ReactComponent as TaskIcon } from "../../assets/menu.svg";
import { ReactComponent as PeopleIcon } from "../../assets/people.svg";
import { ReactComponent as PlannedIcon } from "../../assets/planned.svg";
import { ReactComponent as StarIcon } from "../../assets/star.svg";

function TasksNav() {
  return (
    <div className='w-full h-full bg-secondaryBackground-foreground py-6 text-sidebar-text font-medium'>
      <ul className='h-full flex flex-col '>
        <li className='py-2 px-4 rounded-[16px] flex items-center gap-x-4'>
          <TaskIcon className='w-6 h-6 text-sidebar-text' />
          <p className='text-[15px]'>All tasks</p>
        </li>
        <li className='py-2 px-4 rounded-[6px]  flex items-center gap-x-4 bg-sidebar-bgActive'>
          <CalenderIcon className='w-6 h-6 text-sidebar-textActive' />
          <p className='font-medium text-sidebar-textActive text-[15px]'>
            Today
          </p>
        </li>
        <li className='py-2 px-4 rounded-[16px] flex items-center gap-x-4'>
          <StarIcon className='w-6 h-6 fill-text-primary' />
          <p className='text-[15px]'>Important</p>
        </li>
        <li className='py-2 px-4 rounded-[16px] flex items-center gap-x-4'>
          <PlannedIcon className='w-6 h-6 text-text-primary' />
          <p className='text-[15px]'>Planned</p>
        </li>
        <li className='py-2 px-4 rounded-[16px] flex items-center gap-x-4'>
          <PeopleIcon className='w-6 h-6 text-text-primary' />
          <p className='text-[15px]'>Assigned to me</p>
        </li>
      </ul>
    </div>
  );
}

export default TasksNav;
