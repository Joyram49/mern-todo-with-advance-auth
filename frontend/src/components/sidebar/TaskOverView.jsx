import { ReactComponent as InfoIcon } from "../../assets/info.svg";
import Donut from "./Donut";

function TaskOverView() {
  return (
    <div className='w-full bg-secondaryBackground-foreground  shadow-[0px_1.33px_6.65px_0px_#0000001A] text-sidebar-text'>
      <div className='w-full flex flex-col '>
        <div className='w-full flex justify-between items-start border-b-[1.33px] border-[#f0f0f0] p-4'>
          <div className='font-inter font-medium '>
            <p className='text-[13.3px]'>Today Tasks</p>
            <p className='text-[21.27px]'>11</p>
          </div>
          <div>
            <InfoIcon />
          </div>
        </div>
        <div className='w-full p-4'>
          <Donut />
        </div>
      </div>
    </div>
  );
}

export default TaskOverView;
