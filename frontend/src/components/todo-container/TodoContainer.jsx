import { useState } from "react";
import TodoEdit from "../edit-todo/TodoEdit";
import AddTodo from "./AddTodo";
import Completed from "./Completed";
import Inprogress from "./Inprogress";

function TodoContainer() {
  const [showTodoEdit, setShowTodoEdit] = useState(false);

  return (
    <div
      className={`w-full grid ${
        showTodoEdit ? "grid-cols-[1fr_auto]" : "grid-cols-[1fr]"
      } gap-x-[6px] transition-transform duration-300`}
    >
      {/* Main content */}
      <div className='flex flex-col py-4 gap-y-4'>
        <AddTodo />
        <Inprogress />
        <Completed />
        {/* Toggle button to render TodoEdit */}
        <button
          className='bg-blue-500 text-white py-2 px-4 rounded mt-4'
          onClick={() => setShowTodoEdit(!showTodoEdit)}
        >
          {showTodoEdit ? "Close Editor" : "Open Editor"}
        </button>
      </div>

      {/* Conditional rendering of TodoEdit */}
      {showTodoEdit && <TodoEdit />}
    </div>
  );
}

export default TodoContainer;
