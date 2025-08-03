require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const moongose = require("mongoose");
const app = express();
const authRouter = require("./routers/authRouter");
app.use(cors());
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
moongose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("DB connected");
  })
  .catch((err) => {
    console.log(err);
  });
app.use("/api/auth", authRouter);
app.get("/", (req, res) => {
  res.json({ name: "Hello Buddy!" });
});
app.listen(process.env.PORT, () => {
  console.log("Server running...");
  console.log(process.env.PORT);
});
