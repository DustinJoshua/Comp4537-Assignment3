const { mongoose } = require('mongoose')
const logModel = require('./logModel')

// function handleErr(err) {
//   // console.log("err.name: ", err.name);
//   if (err instanceof mongoose.Error.ValidationError) {
//     return ({ errMsg: "ValidationError: check your ..." })
//   } else if (err instanceof mongoose.Error.CastError) {
//     return ({ errMsg: "CastError: check your ..." })
//   } else {
//     return ({ errMsg: err })
//   }
// }

handleErr = (err, req, res, next) => {
  if (err.pokeErrCode)
    res.status(err.pokeErrCode)
  else
    res.status(500)

    const log = new logModel({
      user: null,
      timestamp: new Date(),
      endpoint: req.path,
      method: req.method,
      status: res.statusCode,
    })
  
    // save log to database
    log.save((err) => {
      if (err) {
        console.error('Error saving log:', err)
      }
    })

  res.send(err.message)
  console.log("####################")
  console.log(err);
  console.log("####################")
  // if (err instanceof PokemonBadRequestMissingAfter) {
  //   res.status(err.code).send(err.message);
  // } else if (err instanceof PokemonBadRequestMissingID) {
  //   res.status(400).send(err.message);
  // } else {
  //   res.status(500).send(err.message);
  // }
}


module.exports = { handleErr }