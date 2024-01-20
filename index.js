const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const UserModel = require("./models/User");
const nodemailer = require("nodemailer");
require("dotenv").config();
PORT = 3000;

const app = express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());

mongoose.connect(process.env.DB_URI);
console.log("db connected ")

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json("Token is missing");
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json("Error with token");
      } else {
        if (decoded.role === "admin") {
          next();
        } else {
          return res.json("not admin");
        }
      }
    });
  }
};

app.get("/dashboard", verifyUser, (req, res) => {
  res.json("Success");
});

app.post("/", (req, res) => {
  const { name, email, password } = req.body;
  bcrypt
    .hash(password, 10)
    .then((hash) => {
      UserModel.create({ name, email, password: hash })
        .then((user) => res.json("Success"))
        .catch((err) => res.json(err));
    })
    .catch((err) => res.json(err));
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  UserModel.findOne({ email: email }).then((user) => {
    if (user) {
      bcrypt.compare(password, user.password, (err, response) => {
        if (response) {
          const token = jwt.sign(
            { email: user.email, role: user.role },
            "jwt-secret-key",
            { expiresIn: "1d" }
          );
          res.cookie("token", token);
          return res.json({ Status: "Success", role: user.role });
        } else {
          return res.json("The password is incorrect");
        }
      });
    } else {
      return res.json("No record existed");
    }
  });
});

app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  UserModel.findOne({ email: email }).then((user) => {
    if (!user) {
      return res.send({ Status: "User not existed" });
    }
    const token = jwt.sign({ id: user._id }, "jwt_secret_key", {
      expiresIn: "30d",
    });

    var transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.user,
        pass: process.env.pass
      },
    });

    var mailOptions = {
      from: "rohit@gmail.com",
      to: process.env.user,
      subject: "Reset Password Link",
      text: `http://localhost:5173/reset-password/${user._id}/${token}`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        return res.send({ Status: "Success" });
      }
    });
  });
});

app.post('/reset-password/:id/:token', (req, res) => {
    const { id, token } = req.params
    const { password } = req.body
    
    jwt.verify(token, "jwt_secret_key", (err, decoded) => {
        if (err) {
            return res.json({Status:"Error with token"})
        } else {
            bcrypt
              .hash(password, 10)
              .then((hash) => {
                UserModel.findByIdAndDelete({ _id: id }, { password: hash })
                  .then(u => res.send({ Status: "Success" }))
                  .catch((err) => res.send({ Sataus: err }));
              })
              .catch((err) => res.send({ Sataus: err }));
        }
    })
})

app.listen(PORT, () => {
  console.log(`server running on PORT ${PORT}`);
});
