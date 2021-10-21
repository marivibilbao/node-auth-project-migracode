const express = require("express");
const cors = require("cors");
const user = require("./routes/user");

// initializing express application
const app = express();

// parse requests of content-type - application/json
app.use(express.json());

const corsOptions = {
  origin: "http://localhost:3000"
};
app.use(cors(corsOptions));  // enable CORS

// simple route
app.get("/", (req, res) => {
  res.json({ message: "Welcome to MigraCode Auth application." });
});

app.use("/user", user);
// set port, listen for requests
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});