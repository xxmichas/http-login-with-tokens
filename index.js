const path = require('path')
const fs = require('fs')
const express = require('express');
const app = express();
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
require('dotenv/config');

//The Server will throw errors if you restart it without logging out on the website due to our "Database" implementation
const poorMansDatabase = []

app.use(express.static(path.join(__dirname, './Client')));
app.use(express.json({limit: '15mb'}))

app.post('/register', async (req, res) => {
    if (req.body.username && req.body.password) {
        for (const user of poorMansDatabase) {
            if (req.body.username === user.username) {
                res.status(409).send("User With This Username Already Exists")
                return
            }
        }
        let id = Date.now()
        let hashedPassword = await bcrypt.hash(req.body.password, 10)
        poorMansDatabase.push({id: id, username: req.body.username, password: hashedPassword})
        console.log(poorMansDatabase)
        res.status(201).send("Account Successfully Created")
    }
    else {
        res.status(400).send("An Error Occurred")
    }
})

app.post('/login', async (req, res) => {
    const authHeader = req.headers['authorization']
    const authToken = authHeader && authHeader.split(' ')[1]
    if (authToken != null) {
        jwt.verify(authToken, process.env.JWT_ACCESS_TOKEN, async (error, user) => {
            if (error) {
                res.status(410).send("Session Expired")
            }
            else{
                let loggingInUser = poorMansDatabase.find(userr => userr.username === user.username)
                const token = jwt.sign(loggingInUser, process.env.JWT_ACCESS_TOKEN, {expiresIn: "7d"})
                res.status(202).send(token)
            }
        })
    }
    else {
        if (req.body.username && req.body.password) {
            let loggingInUser = poorMansDatabase.find(user => user.username === req.body.username)
            if (loggingInUser != null) {
                if (await bcrypt.compare(req.body.password, loggingInUser.password)) {
                    const token = jwt.sign(loggingInUser, process.env.JWT_ACCESS_TOKEN, {expiresIn: "7d"})
                    res.status(202).send(token)
                }
                else {
                    res.status(500).send("Incorrect Username or Password")
                }
            }
            else {
                res.status(400).send("Incorrect Username or Password")
            }
        }
        else {
            res.status(400).send("An Error Occurred")
        }
    }
})

app.post('/myAccount', async (req, res) => {
    const authHeader = req.headers['authorization']
    const authToken = authHeader && authHeader.split(' ')[1]
    if (authToken != null) {
        jwt.verify(authToken, process.env.JWT_ACCESS_TOKEN, async (error, user) => {
            if (error) {
                res.status(410).send("Session Expired")
            }
            else{
                let requsetingUser = poorMansDatabase.find(userr => userr.username === user.username)
                const token = jwt.sign(requsetingUser, process.env.JWT_ACCESS_TOKEN, {expiresIn: "7d"})
                res.status(202).json({token: token, username: requsetingUser.username, id: requsetingUser.id})
            }
        })
    }
    else {
        res.status(400).send("An Error Occurred")
    }
})

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../Client', '404.html'));
});

app.listen(2137, () => {
    console.log('listening on port 2137');
});