export const isAuthenticated = () => {
  const user = localStorage.getItem("user");
  return !!user;
};

export const loginUser = (email, password) => {
  const users = JSON.parse(localStorage.getItem("users")) || [];

  const user = users.find((u) => u.email === email && u.password === password);
  if (user) {
    localStorage.setItem("user", JSON.stringify(user));
    return true;
  }
  return false;
};

export const registerUser = (name, email, password) => {
  const users = JSON.parse(localStorage.getItem("users")) || [];
  const userExists = users.some((u) => u.email === email);
  if (!userExists) {
    users.push({ id: Date.now(), name, email, password });
    localStorage.setItem("users", JSON.stringify(users));
    return true;
  }
  return false;
};

export const logoutUser = () => {
  localStorage.removeItem("user");
};
