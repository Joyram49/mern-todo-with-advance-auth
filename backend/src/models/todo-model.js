import mongoose from "mongoose";

const TodoSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    notes: {
      type: String,
      trim: true,
    },
    isFavourite: {
      type: Boolean,
      default: false,
    },
    scheduleDate: { type: Date },
    dueDate: {
      type: Date,
      default: null,
    },
    reminder: {
      type: Date,
      default: null,
    },
    reminderSentAt: { type: Date },
    status: {
      type: String,
      enum: ["outdated", "inProgress", "completed"],
      default: "inProgress",
    },
    steps: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Step",
      },
    ],
    deletedAt: { type: Date },
    archivedAt: { type: Date },
  },
  { timestamps: true }
);

export const Todo = mongoose.models.Todo ?? mongoose.model("Todo", TodoSchema);
