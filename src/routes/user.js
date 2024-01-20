import express from "express";
import userCrl from "../controller/user.js";

const router = express.Router();

router.post("/signup", userCrl.signup);
router.post("/login", userCrl.login);
router.post("/forget-password", userCrl.forgetPassword);
router.post(
  "/reset-password/:randomString/:expitationTimestamp",
  userCrl.resetPassword
);
router.get("/getAlluser", userCrl.getAllUser);

export default router;
