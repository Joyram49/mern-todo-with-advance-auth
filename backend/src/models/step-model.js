import mongoose, { Schema } from "mongoose";

const StepSchema = new mongoose.Schema(
  {
    todo: { type: Schema.Types.ObjectId, ref: "Todo", required: true },
    title: { type: String, required: true, trim: true },
    isCompleted: { type: Boolean, default: false },
    order: {
      type: Number,
      default: 0,
      required: true,
    },
  },
  { timestamps: true }
);

export const Step = mongoose.models.Step ?? mongoose.model("Step", StepSchema);
