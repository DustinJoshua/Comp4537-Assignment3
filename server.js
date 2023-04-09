// Imports
const mongoose = require("mongoose");
const express = require("express");
const dotenv = require("dotenv");
dotenv.config();
const cors = require("cors");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

// Database connections and models
const { connectDB } = require("./connectDB.js");
const { populatePokemons } = require("./populatePokemons.js");
const { getTypes } = require("./getTypes.js");
const userModel = require("./userModel.js");
const logModel = require("./logModel.js")

// Helpers and error handlers
const { handleErr } = require("./errorHandler.js");
const { asyncWrapper } = require("./asyncWrapper.js");
const {
  PokemonBadRequest,
  PokemonBadRequestMissingID,
  PokemonBadRequestMissingAfter,
  PokemonDbError,
  PokemonNotFoundError,
  PokemonDuplicateError,
  PokemonNoSuchRouteError,
  PokemonAuthError,
} = require("./errors.js");

// Initialize the app
const app = express();
app.use(express.json());
app.use(cors());
app.use(cors({
  exposedHeaders: ['auth-token-access', 'auth-token-refresh']
}))

// Start the server and connect to the database
const start = asyncWrapper(async () => {
  await connectDB({ drop: false });
  const pokeSchema = await getTypes();
    pokeModel = await populatePokemons(pokeSchema);

  // pokeModel = mongoose.model("pokemons", pokeSchema);

  app.listen(process.env.PORT || process.env.SERVER_PORT, async (err) => {
    if (err) throw new PokemonDbError(err);
    else console.log(`Phew! Server is running on port: ${process.env.SERVER_PORT}`);
    const doc = await userModel.findOne({ "username": "admin" })
    if (!doc)
      userModel.create({ username: "admin", password: bcrypt.hashSync("admin", 10), role: "admin", email: "admin@admin.ca" })
  });
});
start();

app.use(morgan(":method"));

const logRequest = asyncWrapper(async (req, res, next) => {
  var accessToken = req.header('auth-token-access')
  var refreshToken = req.header('auth-token-refresh')
  if (!accessToken && !refreshToken) {
    const log = new logModel({
      user: null,
      timestamp: new Date(),
      endpoint: req.path,
      method: req.method,
      status: res.statusCode
    });
  
    await log.save();
    next();
  } else if (accessToken && !refreshToken) {
    const payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET)
    const user = payload.user

    const log = new logModel({
      user: user ? user.username : null,
      timestamp: new Date(),
      endpoint: req.path,
      method: req.method,
      status: res.statusCode
  });

  await log.save();
  next();
  } else {
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)
    const user = payload.user

    const log = new logModel({
      user: user ? user.username : null,
      timestamp: new Date(),
      endpoint: req.path,
      method: req.method,
      status: res.statusCode
  });

  await log.save();
  next();
  }
  
});

app.use(logRequest);

// Authentication
app.post('/register', asyncWrapper(async (req, res) => {
  const { username, password, email } = req.body
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)
  const userWithHashedPassword = { ...req.body, password: hashedPassword }

  const user = await userModel.create(userWithHashedPassword)
  res.send(user)
}))

let refreshTokens = [] // replace with a db
app.post('/requestNewAccessToken', asyncWrapper(async (req, res) => {
  // console.log(req.headers);
  const refreshToken = req.header('auth-token-refresh')
  if (!refreshToken) {
    throw new PokemonAuthError("No Token: Please provide a token.")
  }
  if (!refreshTokens.includes(refreshToken)) { // replaced a db access
    console.log("token: ", refreshToken);
    console.log("refreshTokens", refreshTokens);
    throw new PokemonAuthError("Invalid Token: Please provide a valid token.")
  }
  try {
    const payload = await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)
    const accessToken = jwt.sign({ user: payload.user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '10s' })
    res.header('auth-token-access', accessToken)
    res.send("All good!")
  } catch (error) {
    throw new PokemonAuthError("Invalid Token: Please provide a valid token.")
  }
}))

app.post('/login', asyncWrapper(async (req, res) => {
  const { username, password } = req.body
  const user = await userModel.findOne({ username })
  if (!user)
    throw new PokemonAuthError("User not found")

  const isPasswordCorrect = await bcrypt.compare(password, user.password)
  if (!isPasswordCorrect)
    throw new PokemonAuthError("Password is incorrect")


  const accessToken = jwt.sign({ user: user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '10s' })
  const refreshToken = jwt.sign({ user: user }, process.env.REFRESH_TOKEN_SECRET)
  refreshTokens.push(refreshToken)

  res.header('auth-token-access', accessToken)
  res.header('auth-token-refresh', refreshToken)

  // res.send("All good!")
  res.send(user)
}))


app.get('/logout', asyncWrapper(async (req, res) => {

  const user = await userModel.findOne({ token: req.query.appid })
  if (!user) {
    throw new PokemonAuthError("User not found")
  }
  await userModel.updateOne({ token: user.token }, { token_invalid: true })
  res.send("Logged out")
}))

// API routes
const authUser = asyncWrapper(async (req, res, next) => {
  // const token = req.body.appid
  const token = req.header('auth-token-access')

  if (!token) {
    // throw new PokemonAuthError("No Token: Please provide an appid query parameter.")
    throw new PokemonAuthError("No Token: Please provide the access token using the headers.")
  }
  try {
    const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    next()
  } catch (err) {
    throw new PokemonAuthError("Invalid Token Verification. Log in again.")
  }
})

const authAdmin = asyncWrapper(async (req, res, next) => {
  const payload = jwt.verify(req.header('auth-token-access'), process.env.ACCESS_TOKEN_SECRET)
  if (payload?.user?.role == "admin") {
    return next()
  }
  throw new PokemonAuthError("Access denied")
})

app.use(authUser) // Boom! All routes below this line are protected
app.get('/api/v1/pokemons', asyncWrapper(async (req, res) => {
  if (!req.query["count"])
    req.query["count"] = 10
  if (!req.query["after"])
    req.query["after"] = 0
  // try {
  const docs = await pokeModel.find({})
    .sort({ "id": 1 })
    .skip(req.query["after"])
    .limit(req.query["count"])
  res.json(docs)
  // } catch (err) { res.json(handleErr(err)) }
}))

app.get('/api/v1/pokemon', asyncWrapper(async (req, res) => {
  // try {
  const { id } = req.query
  const docs = await pokeModel.find({ "id": id })
  if (docs.length != 0) res.json(docs)
  else res.json({ errMsg: "Pokemon not found" })
  // } catch (err) { res.json(handleErr(err)) }
}))

// app.get("*", (req, res) => {
//   // res.json({
//   //   msg: "Improper route. Check API docs plz."
//   // })
//   throw new PokemonNoSuchRouteError("");
// })

app.use(authAdmin)
app.post('/api/v1/pokemon/', asyncWrapper(async (req, res) => {
  // try {
  console.log(req.body);
  if (!req.body.id) throw new PokemonBadRequestMissingID()
  const poke = await pokeModel.find({ "id": req.body.id })
  if (poke.length != 0) throw new PokemonDuplicateError()
  const pokeDoc = await pokeModel.create(req.body)
  res.json({
    msg: "Added Successfully"
  })
  // } catch (err) { res.json(handleErr(err)) }
}))

app.delete('/api/v1/pokemon', asyncWrapper(async (req, res) => {
  // try {
  const docs = await pokeModel.findOneAndRemove({ id: req.query.id })
  if (docs)
    res.json({
      msg: "Deleted Successfully"
    })
  else
    // res.json({ errMsg: "Pokemon not found" })
    throw new PokemonNotFoundError("");
  // } catch (err) { res.json(handleErr(err)) }
}))

app.put('/api/v1/pokemon/:id', asyncWrapper(async (req, res) => {
  // try {
  const selection = { id: req.params.id }
  const update = req.body
  const options = {
    new: true,
    runValidators: true,
    overwrite: true
  }
  const doc = await pokeModel.findOneAndUpdate(selection, update, options)
  // console.log(docs);
  if (doc) {
    res.json({
      msg: "Updated Successfully",
      pokeInfo: doc
    })
  } else {
    // res.json({ msg: "Not found", })
    throw new PokemonNotFoundError("");
  }
  // } catch (err) { res.json(handleErr(err)) }
}))

app.patch('/api/v1/pokemon/:id', asyncWrapper(async (req, res) => {
  // try {
  const selection = { id: req.params.id }
  const update = req.body
  const options = {
    new: true,
    runValidators: true
  }
  const doc = await pokeModel.findOneAndUpdate(selection, update, options)
  if (doc) {
    res.json({
      msg: "Updated Successfully",
      pokeInfo: doc
    })
  } else {
    // res.json({  msg: "Not found" })
    throw new PokemonNotFoundError("");
  }
  // } catch (err) { res.json(handleErr(err)) }
}))



app.get('/report', asyncWrapper(async (req, res) => {
  console.log("Report requested");
  const reportId = req.query.id;

  let reportTitle, reportData;
  switch (reportId) {
    case '1':
      reportTitle = 'Unique API users over a period of time';
      const lastWeek = new Date();
      lastWeek.setDate(lastWeek.getDate() - 7);

      const result = await logModel.aggregate([
      {
      $match: {
      timestamp: { $gte: lastWeek }
      }
      },
  {
    $group: {
      _id: {
        user: "$user",
        year: { $year: "$timestamp" },
        month: { $month: "$timestamp" },
        day: { $dayOfMonth: "$timestamp" },
        hour: { $hour: "$timestamp" }
      }
    }
  },
  {
    $group: {
      _id: {
        year: "$_id.year",
        month: "$_id.month",
        day: "$_id.day",
        hour: "$_id.hour"
      },
      uniqueUsers: { $sum: 1 }
    }
  },
  {
    $sort: {
      "_id.year": 1,
      "_id.month": 1,
      "_id.day": 1,
      "_id.hour": 1
    }
  }
]);
console.log('result');
console.log(result);
reportData = result;
      break;
    case '2':
      reportTitle = 'Top API users over a period of time';
      const lastWeek2 = new Date();
      lastWeek2.setDate(lastWeek2.getDate() - 7);

      const result2 = await logModel.aggregate([
        {
          $match: {
            timestamp: { $gte: lastWeek2 }
          }
        },
        {
          $group: {
            _id: "$user",
            count: { $sum: 1 }
          }
        },
        {
          $sort: {
            count: -1
          }
        },
        {
          $limit: 10
        }
      ]);
      console.log('result2');
      console.log(result2);
      reportData = result2;
      break;
    case '3':
      reportTitle = 'Top users for each Endpoint';
      const result3 = await logModel.aggregate([
        {
          $group: {
            _id: {
              endpoint: "$endpoint",
              user: "$user"
            },
            count: { $sum: 1 }
          }
        },
        {
          $sort: {
            "_id.endpoint": 1,
            count: -1
          }
        },
        {
          $group: {
            _id: "$_id.endpoint",
            topUsers: {
              $push: {
                user: "$_id.user",
                count: "$count"
              }
            }
          }
        },
        {
          $project: {
            _id: 1,
            topUsers: { $slice: ["$topUsers", 3] }
          }
        }
      ]);
      console.log('result3');
      console.log(result3);
      reportData = result3;
      break;
    case '4':
      reportTitle = '4xx Errors By Endpoint';
      const result4 = await logModel.aggregate([
        {
          $match: {
            status: { $gte: 400, $lt: 500 }
          }
        },
        {
          $group: {
            _id: {
              endpoint: "$endpoint",
              status: "$status"
            },
            count: { $sum: 1 }
          }
        },
        {
          $match: {
            "_id.status": { $gte: 400, $lt: 500 }
          }
        },
        {
          $sort: {
            "_id.endpoint": 1,
            count: -1
          }
        },
        {
          $group: {
            _id: "$_id.endpoint",
            errors: {
              $push: {
                status: "$_id.status",
                count: "$count"
              }
            }
          }
        }
      ]);
      console.log('result4');
      console.log(result4);
      reportData = result4;
      break;
    case '5':
      reportTitle = 'Recent 4xx/5xx Errors';
      const result5 = await logModel.aggregate([
        {
          $match: {
            status: { $gte: 400, $lt: 600 }
          }
        },
        {
          $sort: {
            timestamp: -1
          }
        },
        {
          $limit: 10
        },
        {
          $group: {
            _id: {
              endpoint: "$endpoint",
              status: "$status"
            },
            count: { $sum: 1 }
          }
        },
        {
          $sort: {
            "_id.endpoint": 1,
            count: -1
          }
        },
        {
          $group: {
            _id: "$_id.endpoint",
            errors: {
              $push: {
                status: "$_id.status",
                count: "$count"
              }
            }
          }
        }
      ]);
      console.log('result5');
      console.log(result5);
      reportData = result5;
      break;
    default:
      res.status(400).send('Invalid report id')
      return;
  }

  res.set('Content-Type', 'application/json').send({ title: reportTitle, data: reportData });
}));

app.use(logRequest);

// Error handling
app.use(handleErr);