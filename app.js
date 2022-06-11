//jshint esversion:6

require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set("view engine", "ejs");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "ourlittlesecret",
  resave: false,
  saveUninitialized: false,
}));

// require('./auth')(passport);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });
// console.log(process.env.API_KEYS);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    // profileFields: ['id']
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', {
    scope: ['profile']
  }));

app.get("/auth/google/secrets",
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
  });

app.get("/auth/facebook",
  passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });


app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })

  .post(function(req, res) {
    User.register({
      username: req.body.username
    }, req.body.password, function(err, user) {
      if (err) {
        console.log(err);
        res.redirect("/reqister");
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    });


  });

app.route("/login")
  .get(function(req, res) {
    res.render("login");
  })

  .post(function(req, res) {

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    req.login(user, function(err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    });


  });


app.get("/secrets", function(req, res) {

  User.find({
    "secrets": {
      $ne: null
    }
  }, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {
          usersWithSecrets: foundUsers
        });
      }
    }

  });


})


app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.route("/submit")
  .get(function(req, res) {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })

  .post(function(req, res) {
    const submittedSecret = req.body.secret;
    // console.log(req.user);
    User.findById(req.user.id, function(err, foundUser) {
      if (err) {
        console.log(err);
      } else {

        if (foundUser) {
          foundUser.secret = submittedSecret;
          foundUser.save(function(err) {
            if (err) {
              console.log(err);
            } else {
              res.redirect("/secrets")
            }
          })
        }
      }
    });
  });

app.listen(3000, function() {
  console.log("server started on port 3000");
});


//////////////////////athentication packages require////////////////////
// require("dotenv").config();
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;



//////////////////////app.post login route////////////////////

// const username = req.body.username;
// const password = req.body.password;
//
// User.findOne({email: username}, function(err, foundUser) {
//   if (err) {
//     console.log(err);
//   } else {
//     if (foundUser) {
//
//       bcrypt.compare(password, foundUser.password, function(err, result) {
//         if (result) {
//           res.render("secrets");
//         } else {
//           res.redirect("/login");
//         }
//       });
//
//     }else {
//       res.redirect("/login");
//     }
//   }
// });


//////////////////////app.post register route////////////////////

// bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//
//   const newUser = new User({
//     email: req.body.username,
//     password: hash
//   });
//
//   newUser.save(function(err) {
//     if (!err) {
//       res.render("secrets");
//     } else {
//       console.log(err);
//     }
//   });
// });
