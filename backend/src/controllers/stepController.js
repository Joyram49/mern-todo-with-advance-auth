/**
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */

async function getSteps(req, res) {
  res.status(200).json({ message: "Hit the get steps route" });
}

async function createStep(req, res) {
  res.status(200).json({ message: "Hit the create step route." });
}

async function updateStep(req, res) {
  res.status(200).json({ message: "Hit the update step route" });
}

async function deleteStep(req, res) {
  res.status(200).json({ message: "Hit the delete step route" });
}

export { createStep, deleteStep, getSteps, updateStep };
