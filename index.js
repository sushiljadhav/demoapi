const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
//const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const cors = require("cors");

const pool = mysql.createPool({
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

app(cors())
// Connect to MySQL
// db.connect((err) => {
//   if (err) {
//     throw err;
//   }
//   console.log('Connected to MySQL');
// });

// Parse JSON request body
app.use(bodyParser.json());

// Middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
   // const token = req.headers.authorization.split(' ')[1];
    console.log(token);
//const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
const decodedToken = jwt.verify(token, process.env.SECRET_KEY, function (err, decoded) {
    if (err) {
      return res.status(400).json({ success: false, message: 'Invalid token.' });
    }
    req.decoded = decoded;
    next();
  });

if (decodedToken.exp <= Math.floor(Date.now() / 1000)) {
    return res.status(401).json({ message: 'Token has expired' });
  }
    if (!token) {
        return res.status(401).send('Access Denied');
    }
    try {
       // const verified = jwt.verify(token, process.env.SECRET_KEY);
       const verified = jwt.verify(token, process.env.SECRET_KEY);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid Token');
    }
};

// REST endpoints
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            throw err;
        }
        const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(sql, [username, email, hash], (err, result) => {
            if (err) {
                throw err;
            }
            res.send('User registered successfully');
        });
    });
});

app.post('/api/login', (req, res) => {
    pool.getConnection(function (err, db) {
        if (err) throw err;

        const { email, password } = req.body;
        const sql = 'SELECT * FROM Users WHERE EmailID = ?';
        db.query(sql, [email], (err, result) => {
            if (err) {
                throw err;
            }
            if (result.length > 0) {
                //   compare(password, result[0].password, (err, match) => {
                //     if (err) {
                //       throw err;
                //     }
                //     if (match) {
                //       const token = jwt.sign({ id: result[0].id }, process.env.SECRET_KEY);
                //       res.header('authorization', token).send('Login successful');
                //     } else {
                //       res.status(401).send('Invalid email or password');
                //     }
                //   });
                console.log(password);
                console.log(result[0].Password);

                if (password === result[0].Password) {
                  //  const token = jwt.sign({  }, process.env.SECRET_KEY);
                    const token = jwt.sign({ id: result[0].UserID }, process.env.SECRET_KEY, { expiresIn: '1m' });
                    res.header('authorization', token).send('Login successful');
                } else {
                    res.status(401).send('Invalid email or password');
                }
            } else {
                res.status(401).send('Invalid email or password');
            }

            db.release();
        });

    });
});

app.get('/api/users', verifyToken, (req, res) => {
    pool.getConnection(function (err, db) {
        if (err) throw err;
        const sql = 'SELECT * FROM Users';
        db.query(sql, (err, result) => {
            if (err) {
               // throw err;
               res.status(400).send('Invalid Token');
            }
            res.send(result);
        });

        db.release();
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

