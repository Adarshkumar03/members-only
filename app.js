require("dotenv/config");
const bcrypt = require("bcryptjs");
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const distanceInWords = require("date-fns/formatDistanceToNow");
const { body, validationResult } = require("express-validator");
var flash = require('connect-flash');

const mongoose = require("mongoose");
const Schema = mongoose.Schema;

mongoose.connect(process.env.MONGO_DEV_URI, { useUnifiedTopology: true, useNewUrlParser: true });

const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    isAdmin: {type: Boolean},
    isMember: {type: Boolean}
  })
);

const Message = mongoose.model(
  "Message", 
  new Schema({
    messageTitle:{type:String, required: true},
    messageText: {type: String, required: true},
    date: {type: Date},
    user: {type: String}
  })
)

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({ secret: "cats", resave: false, saveUninitialized: true , cookie: { secure: false, maxAge: 14400000 }}));
app.use(flash());
passport.use(
  new LocalStrategy((username, password, done)=>{
    User.findOne({username:username}, (err, user)=>{
      if(err){
        return done(err);
      }
      if(!user){
        return done(null, false, {message:"Incorrect username!"});
      }
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user)
        } else {
          // passwords do not match!
          return done(null, false, { message: "Incorrect password" })
        }
      })
    })
  })
);

passport.serializeUser(function(user, done){
  done(null, user.id);
});

passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user){
    done(err, user);
  })
})

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", function(req, res, next){
  Message.find().exec(function(err, message_list){
    if(err){
      return next(err);
    }
    res.render("index", {messages: message_list, format: distanceInWords, user: req.user});
  })
});

app.get("/sign-up", (req, res, next) => res.render("sign-up-form", {user:req.user}));

app.get("/log-in", (req, res, next) => res.render("log-in-form", {user:req.user, messages: req.flash('error')}));

app.get("/membership", function(req, res, next){
  res.render("membership-form", {user: req.user});
});

app.get('/new', function(req, res, next) {
  res.render('new-message-form', {title: "Create new message", user: req.user});
});

app.get("/:id/delete", function(req, res, next){
  res.render('delete-message', {messageId: req.params.id, user:req.user});
});

app.post("/sign-up", [
  body("username")
  .isLength({min:1})
  .withMessage("Username must be specified"),
  body("password")
  .isLength({min: 8})
  .withMessage("Password must be 8 characters long")
  .custom((value,{req, loc, path}) => {
    if (value !== req.body.confirmPassword) {
        throw new Error("Passwords don't match");
    } else {
        return value;
    }
}),
  (req, res, next) => {
  const errors = validationResult(req);
  if(!errors.isEmpty()){
    res.render("sign-up-form", {error: errors.array()[0], user: req.user})
  }
  bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
    if(err){
      return next(err);
    }
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
    });
    if(user.username == process.env.ADMIN_NAME){
      user.isAdmin = true;
      user.isMember = true;
    }else{
      user.isAdmin = false;
      user.isMember=false;
    }
    user.save(err => {
      if(err){
        return next(err);
      }
      res.redirect("/");
    })
  });
}]);

var loginRequired = function(req, res, next) {
  if ( req.isAuthenticated() ) {
      next();
      return
  }
  // Redirect here if logged in successfully
  req.session.redirectTo = req.path;
  res.redirect('/log-in')
}

app.post('/log-in', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
      if ( err ) {
          next(err);
          return
      }
      // User does not exist
      if ( ! user ) {
          req.flash('error', 'Invalid email or password');
          res.redirect('/log-in');
          return
      }
      req.logIn(user, function(err) {
          // Invalid password
          if ( err ) {
              req.flash('error', 'Invalid email or password');
              next(err);
              return
          }
          res.redirect(req.session.redirectTo || '/');
          return
      });
  })(req, res, next);
});

app.post("/membership", (req, res, next) => {
  if(req.body.membershipAnswer == process.env.MEMBERSHIP){ 
    User.findByIdAndUpdate(req.body.userId, {isMember: true}, function(err, user){
      if(err){
        console.log(err);
      }
      console.log("Updated membership status : ", user);
      res.redirect("/");
    });
  }else{
    res.render("membership-form", {error: "Incorrect membership code", user: req.user});
  }
});

app.post('/new', function(req, res, next) {
  let {messageTitle, messageText, userId} = req.body;
  
  User.findById(userId).exec((err, foundUser)=>{
    if(err){
      return next(err);
    }
    let message = new Message({
      messageTitle: messageTitle,
      messageText: messageText,
      date:new Date(),
      user: foundUser.username
    });
    message.save((err)=>{
      if(err){
        return next(err);
      }
      res.redirect("/");
    });
  })
});

app.post("/:id/delete", function(req, res, next){
  Message.findByIdAndRemove(req.params.id, (err) => {
    if(err){
      return next(err);
    }
    console.log("Message deleted successfully!!");
    res.redirect("/");
  })
})

app.get("/log-out", (req, res, next)=>{
    req.logout(function(err){
      if(err){
        return next(err);
      }
      res.redirect("/");
    })
})

app.listen(3000, () => console.log("app listening on port 3000!"));
