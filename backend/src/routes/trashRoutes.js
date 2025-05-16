import express from "express";
const trashRouter = express.Router();

import * as trashController from "../controllers/trashController.js";

// Retrieve all soft-deleted todos with optional filtering/searching
trashRouter.get("/", trashController.getTrash);

// Restore a specific soft-deleted todo
trashRouter.post("/:todoId/restore", trashController.restoreTrashTodo);

// Bulk restore soft-deleted todos
trashRouter.post("/restore", trashController.bulkRestoreTrashTodos);

// Permanently delete a specific soft-deleted todo
trashRouter.delete("/:todoId", trashController.permanentDeleteTodo);

// Bulk permanently delete soft-deleted todos
trashRouter.delete("/", trashController.bulkPermanentDeleteTodos);

export { trashRouter };
