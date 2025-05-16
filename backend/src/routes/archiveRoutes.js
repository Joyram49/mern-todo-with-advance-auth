import express from "express";
const archiveRouter = express.Router();

import * as archiveController from "../controllers/archiveController.js";

// Archive a specific todo
archiveRouter.post("/:todoId/archive", archiveController.archiveTodo);

// Bulk archive todos
archiveRouter.post("/bulk", archiveController.bulkArchiveTodos);

// Retrieve all archived todos (with filtering/searching)
archiveRouter.get("/", archiveController.getArchives);

// Restore a specific archived todo
archiveRouter.post("/:todoId/restore", archiveController.restoreArchiveTodo);

// Bulk restore archived todos
archiveRouter.post("/restore", archiveController.bulkRestoreArchiveTodos);

// Permanently delete an archived todo
archiveRouter.delete("/:todoId", archiveController.deleteArchiveTodo);

// Bulk permanently delete archived todos
archiveRouter.delete("/", archiveController.bulkDeleteArchiveTodos);

export { archiveRouter };
