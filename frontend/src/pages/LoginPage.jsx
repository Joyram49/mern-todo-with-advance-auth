import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { loginUser } from "../utils/auth";

const LoginPage = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();

    const success = loginUser(email, password);
    if (success) {
      navigate("/todo");
    } else {
      setError("Invalid email or password!");
    }
  };

  return (
    <div className='min-h-screen bg-secondaryBackground-foreground flex items-center justify-center'>
      <div className='bg-secondaryBackground-foreground drop-shadow-sm ring-[1px] ring-slate-800/10 rounded-sm p-8 w-full max-w-md'>
        <h2 className='text-2xl font-[800] text-center mb-6 text-[#1B281B] font-sen'>
          Login
        </h2>

        <form onSubmit={handleLogin} className='space-y-4'>
          <div>
            <label className='block text-sm font-medium text-gray-700'>
              Email
            </label>
            <input
              type='email'
              placeholder='Enter your email'
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className='mt-1 w-full p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500'
            />
          </div>
          <div>
            <label className='block text-sm font-medium text-gray-700'>
              Password
            </label>
            <input
              type='password'
              placeholder='Enter your password'
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className='mt-1 w-full p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500'
            />
          </div>
          <button
            type='submit'
            className='w-full bg-gray-800 text-white py-2 rounded-lg hover:bg-gray-900 transition'
          >
            Login
          </button>
        </form>
        {error && (
          <p className='mt-4 text-sm text-red-500 text-center'>{error}</p>
        )}
        <p className='mt-4 text-center text-sm'>
          Not registered?{" "}
          <Link
            to='/register'
            className='text-blue-600 hover:underline font-medium'
          >
            Create an account
          </Link>
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
