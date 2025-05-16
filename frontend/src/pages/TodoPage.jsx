import Header from "../components/header/Header";
import SideBar from "../components/sidebar/Sidebar";
import TodoContainer from "../components/todo-container/TodoContainer";

const TodoPage = () => {
  // const navigate = useNavigate();

  // const handleLogout = () => {
  //   logoutUser();
  //   navigate("/login");
  // };

  return (
    <main className='w-full min-h-screen h-auto  bg-background'>
      <div className='h-full container mx-auto flex flex-col gap-y-[48px] relative'>
        <div>
          <Header />
        </div>
        <div className='w-full h-full flex gap-x-[48px] '>
          <SideBar />
          <TodoContainer />
        </div>
      </div>
    </main>
  );
};

export default TodoPage;
