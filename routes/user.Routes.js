import express from "express";
import UserModel from "../model/user.model.js";
import bcrypt from "bcrypt";
import isAuth from "../middlewares/isAuth.js";
import isAdmin from "../middlewares/isAdmin.js";
import attachCurrentUser from "../middlewares/attachCurrentUser.js";
import generateToken from "../config/jwt.config.js";

const userRoute = express.Router();
const saltRounds = 10;

//SIGNUP

userRoute.post("/sign-up", async (req, res) => {
  try {
    const { password } = req.body;

    if (
      !password ||
      !password.match(
        /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[$*&@#!])[0-9a-zA-Z$*&@#!]{8,}$/,
      )
    ) {
      return res
        .status(400)
        .json({ msg: "A senha não possui os requisitos minimos de seguranca" });
    }

    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = await UserModel.create({
      ...req.body,
      passwordHash: hashedPassword,
    });

    delete newUser._doc.passwordHash;

    return res.status(201).json(newUser);
  } catch (error) {
    console.log(error);
    return res.status(500).json(error.errors);
  }
});

//LOGIN
userRoute.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await UserModel.findOne({ email: email });

    if (!user) {
      return res.status(400).json({ msg: "Usuário não cadastrado" });
    }

    if (await bcrypt.compare(password, user.passwordHash)) {
      delete user._doc.passwordHash;

      const token = generateToken(user);

      return res.status(200).json({
        user: user,
        token: token,
      });
    } else {
      return res.status(401).json({ msg: "Email ou Senha inválidos" });
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json(error);
  }
});

//PROFILE USER
userRoute.get("/profile", isAuth, attachCurrentUser, async (req, res) => {
  try {
    return res.status(200).json(req.currentUser);
  } catch (error) {
    console.log(error);
    return res.status(500).json(error);
  }
});

//PROFILE ADMIN

userRoute.get(
  "/all-users",
  isAuth,
  isAdmin,
  attachCurrentUser,
  async (req, res) => {
    try {
      const users = await UserModel.find({}, { passwordHash: 0 });

      return res.status(200).json(users);
    } catch (error) {
      console.log(error);
      return res.status(500).json(error);
    }
  },
);

export default userRoute;
