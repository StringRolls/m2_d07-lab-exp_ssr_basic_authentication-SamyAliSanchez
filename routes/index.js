const router = require("express").Router();

const {isLoggedin} = require ("../middlewares/auth.middlewares");

router.get("/userProfile", isLoggedin, (req, res) => 
res.render("users/user-profile", {user: req.session.currentUser}));

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

module.exports = router;