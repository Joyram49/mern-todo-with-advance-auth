import mongoose, { Schema } from "mongoose";

const ArchivedTodoSchema = new mongoose.Schema(
  {
    originalTodoId: {
      type: Schema.Types.ObjectId,
      ref: "Todo",
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
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
    archivedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export const ArchivedTodo =
  mongoose.models.ArchivedTodo ??
  mongoose.model("ArchivedTodo", ArchivedTodoSchema);
