import mongoose from "mongoose";

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      loweCase: true,
    },
    password: {
      type: String,
      required: true,
    },
    profile_picture: String,
    refreshTokens: [
      {
        type: String,
      },
    ],
  },
  {
    timestamps: true,
  }
);

export const User = mongoose.models.User ?? mongoose.model("User", UserSchema);
