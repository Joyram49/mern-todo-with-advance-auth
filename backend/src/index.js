import cookieParser from "cookie-parser";
import cors from "cors";
import { config } from "dotenv";
import express from "express";
import { archiveRouter } from "./routes/archiveRoutes.js";
import { authRouter } from "./routes/authRoutes.js";
import { stepRouter } from "./routes/stepRoutes.js";
import { todoRouter } from "./routes/todoRoutes.js";
import { tokenRouter } from "./routes/tokenRoutes.js";
import { trashRouter } from "./routes/trashRoutes.js";
import { userRouter } from "./routes/userRoutes.js";
import { connectMongo } from "./services/dbConnect.js";
import { cascadeDeleteExpiredTrash } from "./utils/cascadeRemoval.js";

const port = process.env.PORT || 9000;

config();
const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.status(200).json({ message: "This is home route" });
});

// routers except the home
app.use("/auth", authRouter);
app.use("/user", userRouter);
app.use("/todos", todoRouter);
app.use("/todos/:todoId/steps", stepRouter);
app.use("/archives", archiveRouter);
app.use("/trash", trashRouter);
app.use("/token", tokenRouter);

connectMongo()
  .then(() => {
    setInterval(cascadeDeleteExpiredTrash, 10 * 60 * 1000);
    app.listen(port, (req, res) => {
      console.log(`🚀 server running on port ${port}`);
    });
  })
  .catch((err) => {
    console.log("Database connection failed!", err.message);
  });

// gracefully shutdown
process.on("SIGINT", async () => {
  console.log("Shutting down gracefully...");
  process.exit(0);
});
