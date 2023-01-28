require('dotenv').config()
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(session({
    secret: "Our small secret key",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const mongoose = require('mongoose');
mongoose.connect("mongodb+srv://<username>:<password>@cluster0.kwefnxq.mongodb.net/<databaseName>", { useNewUrlParser: true});
// userSchema object will work but for enc we need to use mongoose.Schema()
// const userSchema = {
//     email: String,
//     password: String
// };

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose);// hash and salt password and save into mongodb DB.
userSchema.plugin(findOrCreate);

const User = mongoose.model('User', userSchema); //(User-collection name,)

passport.use(User.createStrategy());

passport.serializeUser(function(user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    // values received from .env file.
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});

app.get("/secrets", function(req,res){
    User.find({secret: {$ne: null}}, function(err, user){
        res.render("secrets", {userWithSecret: user});
    });
})

app.get("/logout", function(req,res){
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});

app.get("/auth/google", passport.authenticate('google', {

    scope: ['profile']

}));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
})

app.post("/submit", function(req,res){
    const typedSecret = req.body.secret;
    // the req will contain id and username because of passport.
    const userId = req.user.id;

    User.findById(userId, function(err, user){
        if(err){
            console.log(err);
        }
        else{
            user.secret = typedSecret;
            user.save(function(){
                res.redirect("/secrets");
            });
        }
    })
})

app.post("/register", function(req,res){
    // bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    //     newUser.save(function(err){
    //         if(err){
    //             console.log(err);
    //         }
    //         else{
    //             res.render("secrets");
    //         }
    //     })
    // })
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
})

app.post("/login", function(req,res){
    // const Username = req.body.username;
    // User.findOne({email: Username}, function(err, user){
    //     if(err){
    //         console.log(err);
    //     }
    //     else{
    //         if(user){
    //             bcrypt.compare(req.body.password, user.password, (err, result) =>{
    //                 if(result === true){
    //                     res.render("secrets");
    //                 }
    //             })
    //         }
    //     }
    // })
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

})

app.listen('3000',function(){
    console.log('listening on port 3000');
});