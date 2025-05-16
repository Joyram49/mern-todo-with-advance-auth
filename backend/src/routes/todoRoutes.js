import express from "express";
import * as todoController from "../controllers/todoController.js";
const todoRouter = express.Router();

// Retrieve all todos with filtering, searching, sorting, and pagination
todoRouter.get("/", todoController.getTodos);
// Example query parameters: ?search=meeting&status=active&sortBy=createdAt&order=desc&limit=10&page=1

// Retrieve a specific todo
todoRouter.get("/:todoId", todoController.getTodo);

// Create a new todo
todoRouter.post("/", todoController.createTodo);

// Update an existing todo
todoRouter.patch("/:todoId", todoController.updateTodo);

// Soft delete a todo (moves it to trash)
todoRouter.delete("/:todoId", todoController.deleteTodo);

// Bulk soft delete todos
todoRouter.delete("/", todoController.bulkDeleteTodos);

export { todoRouter };
