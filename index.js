//This is a main file where server runs 


import dotenv from "dotenv"; 
import { app } from './app.js';
import connectDB from "./db/indexdb.js";

// configuration setup
dotenv.config({
    path: "./.env",
  });

// method to connect the db
connectDB() 
  .then(() => {
    app.listen(process.env.PORT || 3000, () => {
      console.log(`Server is running at port: ${process.env.PORT}`);
    });
  })
  .catch((err) => {
    console.log("Mongo db connection failed!!!", err);
  });


app.get('/', function (req, res) {
  res.send('Hello World')
})
