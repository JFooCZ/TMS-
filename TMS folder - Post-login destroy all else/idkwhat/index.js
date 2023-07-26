const express = require("express")
const session = require("express-session")
const bodyParser = require("body-parser")
const mysql = require("mysql")
const app = express()
const port = 3000

// Initialize the app and add middleware
app.set("view engine", "pug") // Setup the pug
app.use(bodyParser.urlencoded({ extended: true })) // Setup the body parser to handle form submits
app.use(session({ secret: "super-secret" })) // Session setup

// Serve static files from the
app.use(express.static("TMS Folder"))

// Establish a MySQL connection
const connection = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "admin",
  database: "managesys" //database name
})

// GET request for the login page
app.get("/", (req, res) => {
  res.render("index")
})

// POST request for handling login form submission
app.post("/", (req, res) => {
  // Handle the form submission here, for example, checking credentials, etc.
  const username = req.body.username
  const password = req.body.password

  // Example check (replace with own authentication logic)
  if (username === "test" && password === "test") {
    // Redirect to the dashboard page (tms.pug) after successful login
    res.redirect("/dashboard")
  } else {
    // If login fails, render the login page with an error message
    res.render("index", { error: "Invalid username or password." })
  }
})
// GET request for the dashboard page
app.get("/dashboard", (req, res) => {
  res.render("tms")
})

// POST request to handle "Create New User" form submission
app.post("/submitUser", (req, res) => {
  const { username, password, email, userstatus, usergroups } = req.body
  // Assuming you have a MySQL query to save the user data to the database
  // Replace the example query with your actual database query

  const sql = "INSERT INTO users (username, password, email, userstatus, usergroups) VALUES (?, ?, ?, ?, ?)"
  const values = [username, password, email, userstatus, usergroups]

  connection.query(sql, values, (err, result) => {
    if (err) {
      console.error("Error inserting new user:", err)
      // Handle the error here (e.g., render an error page)
    } else {
      console.log("New user inserted successfully.")
      // Redirect to the dashboard page after successful form submission
      res.redirect("/dashboard")
    }
  })
})

// app.get("/dashboard", (req, res) => {
//   // Assuming you have a variable 'optionSelected' to store the selected option value
//   const optionSelected = req.query.option || "" // Get the selected option from query parameter

//   res.render("tms", { optionSelected })
// })

// Start the server
app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`)
})
