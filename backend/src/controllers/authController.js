/**
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */

async function login(req, res) {
  console.log(req);
  res.status(200).json({ message: "hit the auth login route" });
}

async function signup(req, res) {
  console.log(req.params);
  res.status(200).json({ message: "hit the auth signup route" });
}

async function refreshToken(req, res) {
  res.status(200).json({ message: "hit the auth refresh access token route" });
}

export { login, refreshToken, signup };
