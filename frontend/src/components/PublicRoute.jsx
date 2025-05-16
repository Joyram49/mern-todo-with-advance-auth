/* eslint-disable react/prop-types */

import { Navigate } from "react-router";
import { isAuthenticated } from "../utils/auth";

function PublicRoute({ children }) {
  const auth = isAuthenticated();
  console.log(auth);
  return auth ? <Navigate to={"/todo"} /> : children;
}

export default PublicRoute;
