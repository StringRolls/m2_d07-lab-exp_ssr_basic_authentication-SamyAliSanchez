// routes/auth.routes.js

const { Router } = require("express");
const router = new Router();

const bcrypt = require("bcrypt");
const saltRounds = 5;

const User = require("../models/User.model");
const res = require("express/lib/response");

// GET route ==> to display the signup form to users
router
  .route("/signup")
  .get((req, res) => res.render("auth/signup"))
  // POST route ==> to process form data
  .post((req, res, next) => {
    // console.log("The form data: ", req.body);
    const { username, password } = req.body;

    bcrypt
      .genSalt(saltRounds) // generated
      .then((salt) => bcrypt.hash(password, salt))
      .then((hashedPassword) => {
        return User.create({
          username,
          password: hashedPassword,
        });
      })
      .then((userFromDB) => {
        // console.log("Newly created user is: ", userFromDB);
        res.redirect("/");
      })
      .catch((error) => next(error));
  });

router
  .route("/login")
  .get((req, res) => res.render("auth/login"))
  .post((req, res) => {
    const { username, password } = req.body;

    User.findOne({ username })
      .then((user) => {
        if (!user) {
          res.render("auth/login", { errorMessage: "Wrong credentials!" });
          return;
        } else {
          if (bcrypt.compareSync(password, user.password)) {
            req.session.currentUser = user;
            res.redirect("/userProfile"); //redirect whatever I want
            return;
          } else {
            res.render("auth/login", { errorMessage: "Wrong credentials!" });
          }
        }
      })
      .catch((err) => console.log(err));
  });

router.get("/userProfile", (req, res) => res.render("users/user-profile"));

module.exports = router;
