const express = require("express");
const app = express();
const path = require('path');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const clientSessions = require('client-sessions');

const HTTP_PORT = process.env.HTTP_PORT || 4000;
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  clientSessions({
    cookieName: 'session', 
    secret: 'o6LjQ5EVNC28ZgK64hDELM18ScpFQr',
    duration: 2 * 60 * 1000, 
    activeDuration: 1000 * 60, 
  })
);
app.use(express.static('public'));
const users = [];
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '/index.html'));
});
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '/register.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '/login.html'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const existingUser = users.find(user => user.username === username);
  if (existingUser) {
      return res.status(400).send('Username already exists');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.send('User registered successfully! You can now <a href="/login">log in</a>.');
});
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).send('Invalid username or password');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.status(400).send('Invalid username or password');
    }
    req.session.user = { username: user.username };
    res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.send(`Welcome to your dashboard, ${req.session.user.username}!`);
});
app.get('/logout', (req, res) => {
    req.session.reset();
    res.redirect('/login');
});
app.listen(HTTP_PORT,()=> {
  console.log(`Server is running on ${HTTP_PORT}`);
});
module.exports = app;