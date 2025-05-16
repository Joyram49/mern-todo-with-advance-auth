/* eslint-disable react/prop-types */
import { Navigate } from "react-router";
import { isAuthenticated } from "../utils/auth";

const ProtectedRoute = ({ children }) => {
  const auth = isAuthenticated();
  return auth ? children : <Navigate to='/login' />;
};

export default ProtectedRoute;
