const mysql = require("mysql2/promise")

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

async function checkgroup(username, group) {
  try {
    const [results] = await pool.execute("SELECT * FROM user WHERE username = ? AND usergroups LIKE ?", [username, `%${group}%`])

    if (results.length > 0) {
      return true // User is part of the group
    } else {
      return false // User is not part of the group
    }
  } catch (err) {
    console.error("Error executing the query:", err)
    throw err // Rethrow the error so it can be handled upstream
  }
}

module.exports = checkgroup
