const mongoose = require('mongoose')


const logSchema = new mongoose.Schema({
  user: String,
  timestamp: Date,
  endpoint: String,
  method: String,
  status: Number
});
module.exports = mongoose.model('logs', logSchema) 





