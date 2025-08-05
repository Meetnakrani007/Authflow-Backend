const express = require("express");
const authController = require("../controllers/authController");
const { identifier } = require("../middleware/identification");
const router = express.Router();

router.post("/signup", authController.signup);
router.post("/signin", authController.signin);
router.post("/signout", identifier, authController.signout);
router.patch("/sent-code", identifier, authController.sendVerificationCode);
router.patch("/verify-code", identifier, authController.verifyVerificationCode);
router.patch("/change-password", identifier, authController.changePassword);
router.patch(
  "/forgot-password-sent-code",
  authController.sendForgotPasswordCode
);
router.patch(
  "/verify-forgot-password-code",
  authController.verifyForgotpasswordCode
);
module.exports = router;
