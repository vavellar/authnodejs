/* imports */

require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Open Route - Public Route
app.get('/', (req, res) => {
  res.status(200).json({
    name: "welcome to our api"
  })
})

// Private Route

app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id

  // check if user exists
  const user = await User.findById(id, '-password')

  if (!user) {
    return res.status(404).json({msg: 'user not found'})
  }

  return res.status(200).json({user})
})


// middleware to check request
function checkToken(req, res, next) {

  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({msg: 'access not allow'})
  }

  try {

    const secret = process.env.SECRET
    jwt.verify(token, secret)

    next()

  } catch (error) {
    return res.status(400).json({ msg: 'invalid token'})
  }

}

//login User Route 
app.post('/auth/login', async (req, res) => {
  const {email, password } = req.body

  // validations

  if(!email) {
    return res.status(422).json({msg: "email required"})
  }

  if(!password) {
    return res.status(422).json({msg: "password required"})
  }

  //check if user exists
  const user = await User.findOne({ email: email })

  if (!user) {
    return res.status(404).json({msg: "email not exists"})
  }

  // check if password match
  const checkPassword = await bcrypt.compare(password, user.password)

  if (!checkPassword) {
    return res.status(422).json({msg: "wrong password"})
  }

  try {
    const secret = process.env.SECRET
    const token = jwt.sign(
      {
        id: user._id
      },
      secret
    )

    res.status(200).json({
      msg: 'authentication successful',
      token
    })
  } 
  catch(error) {
    console.log(error)

    res.status(500).json({mg: 'Server error'})
  }
})

// Register User Route
app.post('/auth/register', async (req, res) => {

  const { name, email, password, confirmpassword } = req.body

  // validations
  // this validations may be done in frontend too

  if(!name) {
    return res.status(422).json({msg: "O nome é obrigatório"})
  }

  if(!email) {
    return res.status(422).json({msg: "O email é obrigatório"})
  }

  if(!password) {
    return res.status(422).json({msg: "A senha é obrigatória"})
  }

  if (password !== confirmpassword) {
    return res.status(422).json({msg: "As senhas diferem"})
  }

  // check if user already exists
  const userExists = await User.findOne({ email: email })

  if (userExists) {
    return res.status(422).json({msg: "email indisponível"})
  }

  // create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // create user
  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try {
    await user.save()
    return res.status(201).json({msg: 'cadastrado com sucesso'}) 
  } 
  catch(error) {
    console.log(error)

    res.status(500).json({mg: 'Server error'})
  }
})

// Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
  .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.iov5j.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`)
  .then(() => {
    app.listen(3000)
    console.log('connect to database')
}).catch((err) => console.log(err))
