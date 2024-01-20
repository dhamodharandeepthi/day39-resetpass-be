import express from "express";
import UserRouter from "./user.js";

const router = express.Router();
router.get("/", (req, res) => {
  res.status(200).send(` <h1> Welcome to our Password Reset backend</h1>`);
});
router.use("/user", UserRouter);

export default router;
