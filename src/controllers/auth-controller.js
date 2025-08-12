const User = require("../models/auth-model");
const bcrypt = require("bcryptjs");

const handleField = (fields) => {
  let errors = [];

  for (let [field, value] of Object.entries(fields)) {
    if (!value || value.trim === "") {
      errors.push({ field, message: `${field} is required` });
    }
  }

  return errors;
};

const register = async (req, res) => {
  const { name, email, password } = req.body;

  const errors = handleField({ name, email, password });
  if (errors.length > 0) return res.status(400).json(errors);

  try {
    const emailExists = await User.findUserByEmail(email);

    if (emailExists)
      return res.status(400).json({ message: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      await User.createUser(name, email, hashedPassword);
    } catch (error) {
      console.error(error);
    }

    res.status(201).json({ message: "User has been created." });
  } catch (error) {
    console.error(error);
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  const errors = handleField({ email, password });
  if (errors.length > 0) return res.status(400).json(errors);

  try {
    const user = await User.findUserByEmail(email);
    if (!user) return res.status(401).json({ message: "Invalid email." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid password." });

    res.status(200).json({
      message: "Login successful",
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  register,
  login,
};
