const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { parse } = require('dotenv');
//const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const pool = mysql.createPool({
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

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
   // console.log(token);

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

    pool.getConnection(function (err, db) {
        if (err) throw err;


    const { username, email, password } = req.body;
    
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            throw err;
        }
        //const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        const sql = 'INSERT INTO `Users`(`UserFname`, `UserLName`, `ContactNo`, `EmailID`, `UserCategory`, `Password`, `ProfilePhoto`, `Address`, `State`, `City`, `Pincode`, `ProfitPercent`, `CreatedAt`, `ChangedAt`, `Gender`, `DateOfBirth`, `CompanyName`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        db.query(sql, [req.body.UserFname, req.body.UserLName, req.body.ContactNo, req.body.EmailID, req.body.UserCategory, hash, req.body.ProfilePhoto, req.body.Address, req.body.State, req.body.City, req.body.Pincode, req.body.ProfitPercent, req.body.CreatedAt, req.body.ChangedAt, req.body.Gender, req.body.DateOfBirth, req.body.CompanyName], (err, result) => {
            if (err) {
                throw err;
            }
            res.send('User registered successfully');
            db.release();
        });
    });
});
});

app.post('/api/login', (req, res) => {
    pool.getConnection(function (err, db) {
        if (err) throw err;
        const crypto = require('crypto');
        const md5Hash = crypto.createHash('md5');
        const { email, password } = req.body;
        console.log(req.body);
       // const jsonObj = JSON.parse(req.body);
        const jsonStr = '{"data": ["apple", "banana", "orange"]}';
        const jsonObj = JSON.parse(jsonStr);
        var PassHs;
        const dataEmail = req.body.email;
        console.log(dataEmail);
        const sql = 'SELECT * FROM Users WHERE EmailID = ?';
        db.query(sql, [email], (err, result) => {
            if (err) {
                throw err;
            }
            if (result.length > 0) {
                
                bcrypt.hash(password, 10, (err, hash) => {
                    if (err) {
                        throw err;
                    }
                    console.log(hash + "-" + result[0].Password);

                    bcrypt.compare(password, result[0].Password, function(err, resultC) {
                        if (err) {
                          // Handle error
                          console.error(err);
                          return;
                        }
                      
                        if (resultC) {
                          // Passwords match
                          const jsonResult = {
                            message : "Login successful"
                          }

                          const token = jwt.sign({ id: result[0].UserID }, process.env.SECRET_KEY, { expiresIn: '60s' });
                          res.header('authorization', token).json(jsonResult);
                        } else {
                          // Passwords do not match
                          res.status(401).send('Invalid email or password');
                        }
                      });


                    // if (result[0].Password === hash) {
                    //     //  const token = jwt.sign({  }, process.env.SECRET_KEY);
                    //       const token = jwt.sign({ id: result[0].UserID }, process.env.SECRET_KEY, { expiresIn: '60s' });
                    //       res.header('authorization', token).send('Login successful');
                    //   } else {
                    //       res.status(401).send('Invalid email or password');
                    //   }
                });

                // PassHs = md5Hash.update(password, 'utf-8').digest('hex');
                // console.log(PassHs + "-" + result[0].Password);
               
            } else {
                const jsonData = {
                    message: 'Invalid user name or password',
                  };

                res.status(401).json(jsonData);
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

