import express from "express";

import * as authController from "../controllers/authController.js";
const authRouter = express.Router();

// Authenticate user and issue JWT
authRouter.post("/login", authController.login);

// Register a new user
authRouter.post("/signup", authController.signup);

// Refresh the JWT token
authRouter.post("/refresh-token", authController.refreshToken);

export { authRouter };
