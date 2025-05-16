/**
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */

async function archiveTodo(req, res) {
  res.status(200).json({ message: "Hit the create archive todo route" });
}

async function bulkArchiveTodos(req, res) {
  res.status(200).json({ message: "Hit the create bulk archive todos route" });
}

async function getArchives(req, res) {
  res.status(200).json({ message: "Hit the get archive todos route" });
}

async function restoreArchiveTodo(req, res) {
  res.status(200).json({ message: "Hit the restore archive todo route" });
}

async function bulkRestoreArchiveTodos(req, res) {
  res.status(200).json({ message: "Hit the bulk restore archive todos route" });
}

async function deleteArchiveTodo(req, res) {
  res.status(200).json({ message: "Hit the delete parchive todo route" });
}

async function bulkDeleteArchiveTodos(req, res) {
  res.status(200).json({ message: "Hit the bulk delete parchive todos route" });
}

export {
  archiveTodo,
  bulkArchiveTodos,
  bulkDeleteArchiveTodos,
  bulkRestoreArchiveTodos,
  deleteArchiveTodo,
  getArchives,
  restoreArchiveTodo,
};
