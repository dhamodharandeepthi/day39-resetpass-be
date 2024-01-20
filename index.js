import express from "express";
import dotenv from "dotenv";

import AppRouter from "./src/routes/index.js";
import cors from "cors";

dotenv.config();

const PORT = process.env.PORT;
const app = express();
app.use(cors());
app.use(express.json());

app.use("/", AppRouter);

app.listen(PORT, () => console.log(`app is listening to port ${PORT}`));
