import { ReactComponent as StarFillIcon } from "../../assets/star-fill.svg";
import { ReactComponent as StarIcon } from "../../assets/star.svg";

function Inprogress() {
  return (
    <div className='w-full flex flex-col'>
      <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
        <div className='w-full flex items-center justify-between px-5 py-6'>
          <form action='' className='flex gap-x-2 items-center'>
            <input
              id='data1'
              type='checkbox'
              className='appearance-none checked:appearance-auto checked:accent-text-primary w-[18px] h-[18px] rounded cursor-pointer border-2 border-text-primary'
            />
            <label htmlFor='data1' className=' text-text-primary text-[15px] '>
              Buy groceries
            </label>
          </form>
          <div>
            <StarIcon className='w-6 h-6 text-text-primary' />
          </div>
        </div>
      </div>
      <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
        <div className='w-full flex items-center justify-between px-5 py-6'>
          <form action='' className='flex gap-x-2 items-center'>
            <input
              id='data2'
              type='checkbox'
              className='appearance-none checked:appearance-auto checked:accent-text-primary w-[18px] h-[18px] rounded cursor-pointer border-2 border-text-primary'
            />
            <label htmlFor='data2' className='text-text-primary text-[15px]'>
              Buy groceries
            </label>
          </form>
          <div>
            <StarFillIcon className='w-6 h-6 text-text-primary' />
          </div>
        </div>
      </div>
      <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
        <div className='w-full flex items-center justify-between px-5 py-6'>
          <form action='' className='flex gap-x-2 items-center'>
            <input
              id='data3'
              type='checkbox'
              className='appearance-none checked:appearance-auto checked:accent-text-primary w-[18px] h-[18px] rounded cursor-pointer border-2 border-text-primary'
            />
            <label htmlFor='data3' className='text-text-primary text-[15px]'>
              Buy groceries
            </label>
          </form>
          <div>
            <StarIcon className='w-6 h-6 text-text-primary' />
          </div>
        </div>
      </div>
      <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
        <div className='w-full flex items-center justify-between px-5 py-6'>
          <form action='' className='flex gap-x-2 items-center text-[15px]'>
            <input
              id='data4'
              type='checkbox'
              className='appearance-none checked:appearance-auto checked:accent-text-primary w-[18px] h-[18px] rounded cursor-pointer border-2 border-text-primary'
            />
            <label htmlFor='data4' className='text-text-primary'>
              Buy groceries
            </label>
          </form>
          <div>
            <StarIcon className='w-6 h-6 text-text-primary' />
          </div>
        </div>
      </div>
      <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
        <div className='w-full flex items-center justify-between px-5 py-6'>
          <form action='' className='flex gap-x-2 items-center'>
            <input
              id='data5'
              type='checkbox'
              className='appearance-none checked:appearance-auto checked:accent-text-primary w-[18px] h-[18px] rounded cursor-pointer border-2 border-text-primary'
            />
            <label htmlFor='data5' className='text-text-primary text-[15px]'>
              Buy groceries
            </label>
          </form>
          <div>
            <StarIcon className='w-6 h-6 text-text-primary text-[15px]' />
          </div>
        </div>
      </div>
    </div>
  );
}

export default Inprogress;
