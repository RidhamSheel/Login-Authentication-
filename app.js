require("dotenv").config();
const express = require("express")
const path = require("path")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const app = express();

app.use(cookieParser());
app.use('/static', express.static('static'));
app.use(express.urlencoded());

// Connecting app to database
mongoose.connect("mongodb://localhost/login", { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true });

// Defining the schema and creating model
const loginSchema = new mongoose.Schema({
    username: String,
    email: {
        type: String,
        unique: true
    },
    pass: String,
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }

    ]
});
var signUp = mongoose.model('signUp', loginSchema);

// Landing page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname + "/views/home.html"));
});

// Signup Form
app.post("/", async (req, res) => {

    try {
        let password = req.body.pass;
        let cpassword = req.body.cpass;
        if (password === cpassword) {

            let securePassword = async (any) => {
                let hash = await bcrypt.hash(any, 10);
                return hash;
            }
            let newPassword = await securePassword(password);

            const signUpData = new signUp({
                username: req.body.username,
                email: req.body.email,
                pass: newPassword
            })

            //Generates token
            const token = jwt.sign({ _id: signUpData._id }, process.env.SECRET_KEY);
            signUpData.tokens = signUpData.tokens.concat({ token: token });

            res.cookie("jwt", token, {
                expires: new Date(Date.now() + 60000),
                httpOnly: true
            });

            await signUpData.save().then(() => {
                res.sendFile(path.join(__dirname + "/views/home.html"));
            }).catch(() => {
                res.status(400).send("Couldn't send to DB ");
            })

        }
        else {
            res.status(400).send("Passwords do not match ");
        }
    } catch (error) {
        res.status(400).send(error);
    }

});

// Login Form
app.post("/welcome", async (req, res) => {
    try {

        let usrnm = req.body.email1;
        let email = req.body.email1;
        let pass = req.body.pass1;

        const user = await signUp.findOne({ $or: [{ email: email }, { username: usrnm }] });
        const isValid = await bcrypt.compare(pass, user.pass);

        const token = jwt.sign({ _id: user._id }, process.env.SECRET_KEY);

        res.cookie("jwt", token, {
            expires: new Date(Date.now() + 60000),
            httpOnly: true
        });

        if (isValid) {
            user.tokens = user.tokens.concat({ token: token });
            await user.save();
            res.sendFile(path.join(__dirname + "/views/welcome.html"));
        } else {
            res.send("Invalid Credentials");
        }

    } catch (error) {
        res.status(400).send("Error");
    }
});

//Secret Page and its authorization
const auth = async (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        const verifyUser = jwt.verify(token, process.env.SECRET_KEY);
        console.log(verifyUser);
        const user = await signUp.findOne({_id: verifyUser._id});
        console.log(user);

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).send("An error occured"+error);
    }
}

app.get("/secret", auth, (req, res) => {
    res.sendFile(path.join(__dirname + "/views/secretPage.html"));
});

// LogOut page
app.get("/logout", auth, async(req, res) =>{
    try {
        req.user.tokens = req.user.tokens.filter( (currUser) => {
            return currUser.token !== req.token;
        });

        res.clearCookie("jwt");
        console.log("Logged Out Successfully");
        await req.user.save();
        res.sendFile(path.join(__dirname + "/views/home.html"));
    } catch (error) {
        res.status(500).send(error);
    }
});

app.listen("80", () => {
    console.log("Server running ");
});