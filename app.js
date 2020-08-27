const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
require('dotenv').config({ path: __dirname + '/.env' })

mongoose.connect(process.env.MONGODB_URI, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true }
    })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

// Set up LocalStrategy, used by passport.authenticate() later
passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({ username: username }, (err, user) => {
            if (err) {
                return done(err);
            };
            if (!user) {
                return done(null, false, { msg: "Incorrect username" });
            }
            bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                    // passwords match! log user in
                    return done(null, user)
                } else {
                    // passwords do not match!
                    return done(null, false, { msg: "Incorrect password" })
                }
            });
        });
    })
);

// Create cookie
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

// Decode cookie
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// Middleware to allow global access to current user
app.use(function (req, res, next) {
    res.locals.currentUser = req.user;
    next();
});

// Index Get
app.get("/", (req, res) => res.render("index", { user: req.user }));

// Signup Get
app.get("/sign-up", (_req, res) => res.render("sign-up-form"));

// Process Signing up
app.post("/sign-up", (req, res, next) => {

    // Hash password first
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if (err) {
            return next(err);
        };

        // Save hashed password to database
        new User({
            username: req.body.username,
            password: hashedPassword
        }).save(err => {
            if (err) {
                return next(err);
            };
            res.redirect("/");
        });
    });
});

// Process logging in
app.post(
    "/log-in",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/"
    })
);

// Process logging out
app.get("/log-out", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.listen(3000, () => console.log("app listening on port 3000!"));