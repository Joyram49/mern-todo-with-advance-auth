import express from "express";
const userRouter = express.Router();

import * as userController from "../controllers/userController.js";

// Get current user profile
userRouter.get("/me", userController.getUser);

// Update current user profile
userRouter.patch("/me", userController.updateUser);

export { userRouter };
