const jwt = require("jsonwebtoken");
require("dotenv").config();

function authenticate(req, res, next) {
  // Get token from request headers
  let token = req.header("authorization");

  // Check if token exists
  if (!token) {
    return res
      .status(403)
      .send({ message: "authorization denied", isAuthenticated: false });
  }

  token = token.split(" ")[1];

  // Verify token using jwt
  try {
    /* this will return the user id (user:{id: user_id}) which we 
    provided as payload while generating JWT token */
    const verify = jwt.verify(token, process.env.jwtSecret);

    req.user = verify.user;

    next();
  } catch (err) {
    res
      .status(401)
      .send({ message: "Token is not valid", isAuthenticated: false });
  }
}

module.exports = authenticate; // we export it to use it inside user router
