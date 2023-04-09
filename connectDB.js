const { mongoose } = require('mongoose')
const dotenv = require("dotenv")
dotenv.config();
// console.log(process.env)

const connectDB = async (input) => {
  try {
    const x = await mongoose.connect('mongodb+srv://dustinlott:b4q7fA8b6mEjNqnO@cluster13.1tmnkgu.mongodb.net/test?retryWrites=true&w=majority')
    console.log("Connected to db");
    if (input.drop === true)
      mongoose.connection.db.dropDatabase();
    // console.log("Dropped db");
    // get the data from Github 
  } catch (error) {
    console.log('db error ' + error);
  }
}

module.exports = { connectDB }