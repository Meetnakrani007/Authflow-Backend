const express = require("express");
const authController = require("../controllers/authController");
const router = express.Router();

router.post("/signup", authController.signup);
router.post("/signin", authController.signin);
router.post("/signout", authController.signout);
router.patch("/sent-code", authController.sendVerificationCode);
router.patch("/verify-code", authController.verifyVerificationCode);
module.exports = router;
