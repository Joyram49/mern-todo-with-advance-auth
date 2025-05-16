/**
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */

async function getTodos(req, res) {
  res.status(200).json({ message: "Hit the get todos route" });
}

async function getTodo(req, res) {
  res.status(200).json({ message: "Hit the get todo route" });
}

async function createTodo(req, res) {
  res.status(200).json({ message: "Hit the create todo route" });
}

async function updateTodo(req, res) {
  res.status(200).json({ message: "Hit the update todo route" });
}

async function deleteTodo(req, res) {
  res.status(200).json({ message: "Hit the delete todo route" });
}

async function bulkDeleteTodos(req, res) {
  res.status(200).json({ message: "Hit the bulk delete todos route" });
}

export {
  bulkDeleteTodos,
  createTodo,
  deleteTodo,
  getTodo,
  getTodos,
  updateTodo,
};
