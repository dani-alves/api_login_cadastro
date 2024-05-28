require('dotenv').config()
const express = require('express')
const mysql = require('mysql2')
const bcrypt = require('bcryptjs')
const bodyParser = require('body-parser')
const app = express()
const port = 4000
// Configurando o banco de dados
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
  })
// Conectar ao banco de dados
db.connect((err) => {
    if (err) {
      throw err
    }
    console.log('Conectado ao banco de dados MySQL')
  })
// Middleware para análise de corpos JSON
app.use(bodyParser.json())

// Rota para registro de usuário
app.post('/register', async (req, res) => {
  try {
    const { nome, email, password } = req.body
    const hashedPassword = await bcrypt.hash(password, 10)
    db.query('INSERT INTO users (nome, email, password) VALUES (?, ?, ?)', [nome, email, hashedPassword], (err, result) => {
      if (err) {
        console.log(err)
        res.status(500).send('Erro ao registrar usuário')
      } else {
        res.status(201).send('Usuário registrado com sucesso')
      }
    })
  } catch (error) {
    console.log(error);
    res.status(500).send('Erro ao registrar usuário')
  }
})
// Rota para login de usuário
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.log(err)
        res.status(500).send('Erro ao fazer login')
      } else {
        if (results.length > 0) {
          const match = await bcrypt.compare(password, results[0].password)
          if (match) {
            res.status(200).send('Login bem-sucedido')
          } else {
            res.status(401).send('Credenciais inválidas')
          }
        } else {
          res.status(401).send('Credenciais inválidas')
        }
      }
    })
  } catch (error) {
    console.log(error)
    res.status(500).send('Erro ao fazer login')
  }
})
// Inicia o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`)
})