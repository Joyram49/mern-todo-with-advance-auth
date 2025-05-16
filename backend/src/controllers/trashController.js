/**
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */

async function getTrash(req, res) {
  res.status(200).json({ message: "Hit the get trash todos route" });
}

async function restoreTrashTodo(req, res) {
  res.status(200).json({ message: "Hit the restore trash todo route" });
}

async function bulkRestoreTrashTodos(req, res) {
  res.status(200).json({ message: "Hit the bulk restore trash todo route" });
}

async function permanentDeleteTodo(req, res) {
  res.status(200).json({ message: "Hit the permanent delete todo route" });
}

async function bulkPermanentDeleteTodos(req, res) {
  res
    .status(200)
    .json({ message: "Hit the bulk permanent delete todos route" });
}

export {
  bulkPermanentDeleteTodos,
  bulkRestoreTrashTodos,
  getTrash,
  permanentDeleteTodo,
  restoreTrashTodo,
};
