import mongoose, { Schema } from "mongoose";

const trashTodoSchema = new mongoose.Schema(
  {
    originalTodoId: {
      type: Schema.Types.ObjectId,
      ref: "Todo",
      required: true,
    },
    user: { type: Schema.Types.ObjectId, ref: "User", required: true },
    title: { type: String, required: true },
    notes: { type: String },
    isImportant: { type: Boolean, default: false },
    scheduleDate: { type: Date },
    dueDate: { type: Date },
    reminder: { type: Boolean, default: false },
    status: {
      type: String,
      enum: ["active", "completed", "not completed"],
      default: "active",
    },
    // Store the IDs of steps associated with this todo.
    steps: [{ type: Schema.Types.ObjectId, ref: "Step" }],
    // TTL index: document expires 7 days after this timestamp.
    deletedAt: { type: Date, default: Date.now, index: { expires: "7d" } },
  },
  { timestamps: true }
);

export const TrashTodo =
  mongoose.models.TrashTodo ?? mongoose.model("TrashTodo", trashTodoSchema);
