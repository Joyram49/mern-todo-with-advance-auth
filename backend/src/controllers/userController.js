/**
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */

async function getUser(req, res) {
  res.status(200).json({ message: "hit the get user route" });
}

async function updateUser(req, res) {
  res.status(200).json({ message: "hit the update user route" });
}

export { getUser, updateUser };
