const express = require("express");
const User = require("../models/user");
const authController = require("../controllers/auth");
const { check, body } = require("express-validator/check");

const router = express.Router();

router.get("/login", authController.getLogin);

router.get("/signup", authController.getSignup);

router.get("/reset", authController.getReset);

router.post(
  "/login",
  body("email")
    .isEmail()
    .withMessage("Please Enter Valid email"),
  authController.postLogin
);

router.post(
  "/signup",
  [
    check("email")
      .isEmail()
      .withMessage("Please Enter a valid email")
      .custom((val, { req }) => {
        return User.findOne({ email: val }).then(userDoc => {
          if (userDoc) {
            return Promise.reject(
              "Email is already registered. Please pick different one"
            );
          }
        });
      }),
    body(
      "password",
      "Password should be minimum length 5 characters and Alpha neumaric characters"
    )
      .isLength({ min: 5 })
      .isAlphanumeric(),
    body("confirmPassword").custom((value, { req }) => {
      if (req.body.password !== value)
        throw new Error("Passwords have to match");
      return true;
    })
  ],
  authController.postSignup
);

router.post("/logout", authController.postLogout);

router.post("/reset", authController.postReset);

router.get("/reset/:token", authController.getNewPassword);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
