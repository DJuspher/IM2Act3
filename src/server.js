const express = require("express");
const app = express();
const { createTableUsers } = require("./models/auth-model");

app.use(express.json());

createTableUsers()
  .then(() => console.log("Table user created"))
  .catch((error) => console.log(error));

app.use("/api/auth", require("./routes/auth-route"));

app.listen(5000, () => {
  console.log(`Server is running`);
});
