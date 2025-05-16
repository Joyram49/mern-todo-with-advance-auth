import AddList from "./AddList";
import TaskOverView from "./TaskOverView";
import TasksNav from "./TasksNav";

function SideBar() {
  return (
    <div className='w-full max-w-[280px] bg-secondaryBackground flex flex-col items-center gap-[9px] px-[18px] py-3 '>
      <h1 className='w-full font-outfit font-[500] text-[15px] text-text-primary'>
        Hey, ABCD{" "}
      </h1>
      <TasksNav />
      <AddList />
      <TaskOverView />
    </div>
  );
}

export default SideBar;
