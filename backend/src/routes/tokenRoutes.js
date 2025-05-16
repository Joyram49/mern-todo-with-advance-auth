import express from "express";
const tokenRouter = express.Router();

tokenRouter.get("/", (req, res) => {
  res.status(200).json({ message: "Inside token route" });
});

export { tokenRouter };
