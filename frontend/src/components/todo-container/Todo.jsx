import { ReactComponent as StarIcon } from "../../assets/star.svg";

function Todo() {
  return (
    <div className='w-full border-t-[1.5px] border-[#496E4B33] '>
      <div className='w-full flex items-center justify-between px-5 py-6'>
        <form action='' className='flex gap-x-2 items-center'>
          <input
            id='data1'
            type='checkbox'
            className='accent-text-primary w-[18px] h-[18px] rounded cursor-pointer checked:border-text-primary'
          />
          <label htmlFor='data1' className=' text-text-primary text-[15px] '>
            Buy groceries
          </label>
        </form>
        <div>
          <StarIcon className='w-6 h-6 text-black' />
        </div>
      </div>
    </div>
  );
}

export default Todo;
