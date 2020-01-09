const User = require("../models/user");
const nodemailer = require("nodemailer");
const sendGridTransport = require("nodemailer-sendgrid-transport");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { validationResult } = require("express-validator");

const transporter = nodemailer.createTransport(sendGridTransport({
  auth: {
    api_key: process.env.SEND_GRID_API
  }
}));
exports.getLogin = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
    oldInput: {
      email: "",
      password: ""
    },
    validationErrors: []
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
    oldInput: {
      email: "",
      password: "",
      confirmPassword: ""
    },
    validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render("auth/login", {
      path: "/login",
      pageTitle: "Login",
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password
      },
      validationErrors: errors.array()
    });
  }
  User.findOne({ email: email })
    .then(user => {
      if (user) {
        return bcrypt
          .compare(password, user.password)
          .then(doMatch => {
            if (doMatch) {
              req.session.isLoggedIn = true;
              req.session.user = user;
              return req.session.save(err => {
                if (err) console.log(err);
                return res.redirect("/");
              });
            }
            return res.status(422).render("auth/login", {
              path: "/login",
              pageTitle: "Login",
              errorMessage: "Invalid email or Password",
              oldInput: {
                email: email,
                password: password
              },
              validationErrors: []
            });
          })
          .catch(err => {
            console.log(err);
            return res.status(422).render("auth/login", {
              path: "/login",
              pageTitle: "Login",
              errorMessage: "Invalid email or Password",
              oldInput: {
                email: email,
                password: password
              },
              validationErrors: []
            });
          });
      } else {
        console.log("No User with that email");
        return res.status(422).render("auth/login", {
          path: "/login",
          pageTitle: "Login",
          errorMessage: "Invalid email or Password",
          oldInput: {
            email: email,
            password: password
          },
          validationErrors: []
        });
      }
    })
    .catch(err => {
      if (err) console.log(err);
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render("auth/signup", {
      path: "/signup",
      pageTitle: "Signup",
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword
      },
      validationErrors: errors.array()
    });
  }
  bcrypt
    .hash(password, 12)
    .then(hashedPassword => {
      const newUser = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] }
      });
      return newUser.save();
    })
    .then(result => {
      res.redirect("/login");
      transporter
        .sendMail({
          to: email,
          from: "node_booK-shop@gmail.com",
          subject: "Signup Succeeded",
          html: "<h1> You are Successfully Signed Up </h1>"
        })
        .then(res => {
          console.log("Mail Sent ", res);
        })
        .catch(err => console.log(err));
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect("/");
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message
  });
};

exports.getNewPassword = (req, res, next) => {
  console.log("in getNewPassword");
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
    .then(user => {
      if (!user) {
        req.flash("error", "Reset Password Link got Expired");
        return res.redirect("/reset");
      }
      return res.render("auth/new-password", {
        path: "/new-password",
        pageTitle: "New Password",
        errorMessage: message,
        userId: user._id.toString(),
        resetToken: token
      });
    })
    .catch(error => {
      console.log("Error while fetching resetToken", error);
    });
};
exports.postReset = (req, res, next) => {
  const email = req.body.email;
  let token = null;
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      return res.redirect("/reset");
    }
    token = buffer.toString("hex");
    User.findOne({ email: email })
      .then(userDoc => {
        if (!userDoc) {
          console.log("email is already registered.");
          req.flash("error", "No Account is registered with this email");
          return res.redirect("/reset");
        }
        userDoc.resetToken = token;
        userDoc.resetTokenExpiration = Date.now() + 3600000;
        return userDoc.save();
      })
      .then(result => {
        res.redirect("/");
        transporter
          .sendMail({
            to: req.body.email,
            from: "node_booK-shop@gmail.com",
            subject: "Reset Password !",
            html: `
        <h2> You requested to Reset Password </h2>
        <p>Click the <a href="http://localhost:3000/reset/${token}">link</a> to reset Your Password</p>
        `
          })
          .then(res => {
            console.log("Mail Sent ", res);
          })
          .catch(err => console.log(err));
      });
  });
};

exports.postNewPassword = (req, res, next) => {
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  const resetToken = req.body.resetToken;
  const userId = req.body.userId;
  let user = null;
  User.findOne({
    resetToken: resetToken,
    resetTokenExpiration: { $gt: Date.now() },
    _id: userId
  })
    .then(userDoc => {
      if (!userDoc) {
        console.log("Token Has Expired");
        req.flash("error", "Link got expired. Please try again");
        return res.redirect("/reset");
      }
      user = userDoc;
      return bcrypt
        .hash(password, 12)
        .then(hashedPassword => {
          user.password = hashedPassword;
          user.resetToken = undefined;
          user.resetTokenExpiration = undefined;
          return user.save();
        })
        .then(result => {
          req.session.isLoggedIn = true;
          req.session.user = user;
          req.session.save(err => {
            if (err) console.log("Error While Saving the session \n", err);
            return res.redirect("/");
          });
          transporter
            .sendMail({
              to: user.email,
              from: "node_booK-shop@gmail.com",
              subject: "Reseted Password Successful",
              html: "<h1> You are Successfully Updated your Password </h1>"
            })
            .then(res => {
              console.log("Mail Sent ", res);
            })
            .catch(err => console.log("Error While Sending the Mail", err));
        });
    })
    .catch(err => console.error(err));
};
