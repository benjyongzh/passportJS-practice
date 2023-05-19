const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs");

//========================== DB connect ==========================
require("dotenv").config();
const mongodb = process.env.MONGODB_URI;
mongoose.connect(mongodb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongoose connection error"));

//========================== models ==========================
const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

//========================== views ==========================
const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

//========================== passport middleware ==========================
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });

      //check username
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }

      //check password
      bcrypt.compare(password, user.password, (err, res) => {
        if (err) {
          console.log("error in bcrypt compare: " + err);
          return done(err);
        }
        if (res) {
          //password matches. log in
          console.log("passwords match");
          return done(null, user);
        } else {
          //password no match
          console.log("passwords do not match");
          return done(null, false, { message: "Incorrect password" });
        }
      });

      return;
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// ========================= use locals ============================
app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

//========================== routes ==========================
app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

app.get("/sign-up", (req, res) => {
  res.render("sign-up-form");
});

app.post("/sign-up", async (req, res, next) => {
  //validate and sanitize form here

  try {
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      const user = new User({
        username: req.body.username,
        password: hashedPassword,
      });
      const result = await user.save();

      res.redirect("/");
    });
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

//========================== port ==========================
app.listen(3000, () => {
  console.log("app listeining on port 3000.");
});
