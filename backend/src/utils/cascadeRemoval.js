import { Step } from "../models/step-model.js";
import { TrashTodo } from "../models/trashTodo-model.js";

async function cascadeDeleteExpiredTrash() {
  try {
    const cutOffDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const expiredTrashTodos = await TrashTodo.find({
      deletedAt: { $lte: cutOffDate },
    });

    if (expiredTrashTodos.length > 0) {
      for (const trashTodo of expiredTrashTodos) {
        await Step.deleteMany({ _id: { $in: trashTodo.steps } });
        await TrashTodo.deleteOne({ _id: trashTodo._id });
      }
    } else {
      console.log("No expired trash todos found for cascade deletion");
    }
  } catch (error) {
    console.error("Error during cascade deletion:", err);
  }
}

export { cascadeDeleteExpiredTrash };
