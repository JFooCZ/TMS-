// normal folder has been updated. May now be used as prototype for jwt testing.
const express = require("express")
const session = require("express-session")
const bodyParser = require("body-parser")
const mysql = require("mysql2/promise")
const cors = require("cors")
const app = express()
const port = 3000
var bcrypt = require("bcryptjs")
const dotenv = require("dotenv")
const jwt = require("jsonwebtoken")
const Checkgroup = require("./checkgroup")

var corsOptions = {
  origin: "http://localhost:4200"
}

dotenv.config()
let PORT = process.env.PORT || 3000

// Inititalize the app and add middleware
app.set("view engine", "pug") // Setup the pug
app.use(bodyParser.urlencoded({ extended: true })) // Setup the body parser to handle form submits
app.use(session({ secret: "super-secret" })) // Session setup

// Db Configuration
const dbConfig = {
  host: "localhost",
  port: 3306,
  database: "managesys", //database name
  user: "root",
  password: "admin"
}

// Create a MySQL connection pool
const pool = mysql.createPool(dbConfig)

/* ----------------Login Functionalities------------------*/
// Login function
app.post("/login", (req, res) => {
  const username = req.body.username
  const usernameRegex = /^[a-zA-Z0-9_\-]{1,200}$/
  if (!usernameRegex.test(username)) {
    res.json({ error: "Username should be alphanumeric; underscore, and hyphen characters are allowed." })
    return
  }

  const password = req.body.password

  // Check if username and password are not empty
  if (!username || !password) {
    res.json({ error: "Please enter your username/password" })
    return
  }

  // Check the username and password against the database
  pool
    .execute("SELECT * FROM user WHERE username = ?", [username])
    .then(([results]) => {
      if (results.length < 1) {
        res.json({ error: "Username and/or password is incorrect" })
        return
      }

      if (results[0].userstatus === 0) {
        res.json({ error: "Username and/or password is incorrect" })
        return
      }

      // Check if the provided password matches the stored password
      // synchronous bcrypt compare() function
      const match = bcrypt.compareSync(password, results[0].password)
      if (!match) {
        res.json({ error: "Username and/or password is incorrect" })
        return
      }

      // Store the username in the session
      req.session.isLoggedIn = true
      req.session.username = username

      res.json({ error: null, response: "success" })
    })
    .catch((err) => {
      console.error("Error while comparing username/password:", err)
      res.json({ error: "Internal server error" })
    })
})

/* ---------------------Logout Functionality--------------- */
// Logout function
app.get("/logout", (req, res) => {
  // Set isLoggedIn to false to log the user out
  req.session.isLoggedIn = false

  res.json({ logout: "You are logged out" })
})

/* --------------- Create new user functionality----------*/
// Create New User function
app.post("/createnewuser", async (req, res) => {
  // Check if the user is logged in
  if (!req.session.isLoggedIn) {
    res.json({ error: "You are logged out!" })
    return
  }

  const { username, password, email, usergroups, userstatus } = req.body

  // Apply regex to username to prevent sql injection
  const usernameRegex = /^[a-zA-Z0-9_\-]{1,200}$/
  if (!usernameRegex.test(username)) {
    res.json({ error: "Username should be alphanumeric; underscore, and hyphen characters are allowed." })
    return
  }

  try {
    const [rows] = await pool.execute("SELECT * FROM user WHERE username = ?", [username])

    if (rows.length > 0) {
      // Check if username exists
      if (rows.some((user) => user.username === username)) {
        res.json({ error: "Username is already in use" })
        return
      }
    }

    // Validate password and email
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,10}$/
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

    if (!passwordRegex.test(password) || (email && !emailRegex.test(email))) {
      res.json({ error: "Email and/or password is invalid" })
      return
    }

    const hashedDBPassword = bcrypt.hashSync(password, 10)

    // Insert the new user into the database
    await pool.execute("INSERT INTO user (username, email, password, usergroups, userstatus) VALUES (?, ?, ?, ?, ?)", [username, email || null, hashedDBPassword, usergroups || null, userstatus || null])

    res.json({ error: null, response: "success" })
  } catch (err) {
    console.error("Error executing the query:", err)
    res.json({ error: "Internal server error" })
  }
})

// Change Password function
app.post("/changepassword", async (req, res) => {
  // Check if the user is logged in
  if (!req.session.isLoggedIn) {
    return res.json({ error: "You are logged out!" })
  }

  const { username, newPassword } = req.body

  const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,10}$/
  if (!passwordRegex.test(newPassword)) {
    res.json({ error: "Password is invalid" })
    return
  }

  // Check if the username exists in the database
  try {
    const [results] = await pool.execute("SELECT * FROM user WHERE username = ?", [username])
    if (results.length === 0) {
      res.json({ error: "Username does not exist!" })
      return
    }

    const hashedDBPassword = bcrypt.hashSync(newPassword, 10)

    // Update the password for the given username
    await pool.execute("UPDATE user SET password = ? WHERE username = ?", [hashedDBPassword, username])

    res.json({ error: null, response: "success" })
  } catch (err) {
    console.error("Error executing the query:", err)
    res.json({ error: "Internal server error" })
  }
})

/* ---------------------Get all user info----------------*/
// Get All Users Details function
app.get("/getallusers", async (req, res) => {
  // Check if the user is logged in
  if (!req.session.isLoggedIn) {
    res.json({ error: "You are logged out!" })
    return
  }

  try {
    // Fetch all user details from the database
    const [results] = await pool.execute("SELECT username, password, email, usergroups, userstatus FROM user")

    res.json({ error: null, response: results })
  } catch (err) {
    console.error("Error executing the query:", err)
    res.json({ error: "Internal server error" })
  }
})
/*----------- Create new usergroups-------------*/
// Create New User Group function
app.post("/createusergroup", async (req, res) => {
  // Check if the user is logged in
  if (!req.session.isLoggedIn) {
    res.json({ error: "You are logged out!" })
    return
  }

  const { usergroups } = req.body

  try {
    // Check if usergroup already exists in the database
    const [results] = await pool.execute("SELECT * FROM usergroups WHERE usergroups = ?", [usergroups])

    if (results.length > 0) {
      res.json({ error: "User group is already in use" })
      return
    }

    // Insert the new user group into the database
    const [result] = await pool.execute("INSERT INTO usergroups (usergroups) VALUES (?)", [usergroups])

    res.json({ error: null, response: "success" })
  } catch (err) {
    console.error("Error executing the query:", err)
    res.json({ error: "Internal server error" })
  }
})

/* --------------Get all User Groups function---------- */
// Get all User Groups function
app.get("/getallusergroups", async (req, res) => {
  // Check if the user is logged in
  if (!req.session.isLoggedIn) {
    res.json({ error: "You are logged out!" })
    return
  }

  try {
    // Fetch all user group details from db
    const [results] = await pool.execute("SELECT usergroups FROM usergroups")

    res.json({ error: null, response: results })
  } catch (err) {
    console.error("Error executing the query:", err)
    res.json({ error: "Internal server error" })
  }
})

/*---------------Change User Details function--------------*/
app.post("/changeuserdetails", async (req, res) => {
  // Check if the user is logged in
  if (!req.session.isLoggedIn) {
    return res.json({ error: "You are logged out!" })
  }

  const { username, newPassword, newEmail, newStatus, newUsergroups } = req.body

  // Apply regex to inputs to prevent SQL injection
  const usernameRegex = /^[a-zA-Z0-9_\-]{1,200}$/
  const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,10}$/
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  const usergroupsRegex = /^[a-zA-Z0-9_\-]{1,200}$/

  if (!usernameRegex.test(username) || !passwordRegex.test(newPassword) || (newEmail && !emailRegex.test(newEmail)) || (newUsergroups && !usergroupsRegex.test(newUsergroups))) {
    res.json({ error: "Inputs are invalid" })
    return
  }

  // Convert newStatus to boolean
  const userStatus = Boolean(newStatus)

  try {
    // Check if the username exists in the database
    const [results] = await pool.execute("SELECT * FROM user WHERE username = ?", [username])

    if (results.length === 0) {
      res.json({ error: "Username does not exist!" })
      return
    }

    const hashedDBPassword = bcrypt.hashSync(newPassword, 10)

    let query = "UPDATE user SET password = ?"
    let params = [hashedDBPassword]

    // Add fields to the query if they were provided
    if (newEmail) {
      query += ", email = ?"
      params.push(newEmail)
    }
    if (newUsergroups) {
      query += ", usergroups = ?"
      params.push(newUsergroups)
    }

    query += ", userstatus = ? WHERE username = ?"
    params.push(userStatus, username)

    // Update the password, email, and status for the given username
    const [updateResult] = await pool.execute("UPDATE user SET password = ?, email = ?, userstatus = ?, usergroups = ? WHERE username = ?", [hashedDBPassword, newEmail || null, userStatus, newUsergroups || null, username])

    res.json({ error: null, response: "success" })
  } catch (err) {
    console.error("Error executing the query:", err)
    res.json({ error: "Internal server error" })
  }
})

//app listening at port 3000
app.listen(port, () => {
  console.log(`Server is running on port ${port}.`)
})
