import express from "express";
import * as stepController from "../controllers/stepController.js";
const stepRouter = express.Router();

// Retrieve all steps for a specific todo
stepRouter.get("/", stepController.getSteps);

// Create a new step for a specific todo
stepRouter.post("/", stepController.createStep);

// Update a specific step
stepRouter.patch("/:stepId", stepController.updateStep);

// Delete a specific step
stepRouter.delete("/:stepId", stepController.deleteStep);

export { stepRouter };
