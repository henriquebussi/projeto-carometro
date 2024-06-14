const express = require("express")
const Mysql = require('mysql2')
const cors = require('cors')
const bodyParser = require('body-parser')
const session = require('express-session')
const bcrypt = require('bcrypt')
const { log } = require("console")
require('dotenv').config()

const app = express()

app.use(cors())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

const db = Mysql.createConnection({
    host: process.env.DB_HOST,
    user:  process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
})

db.connect(err =>{
    if(err){
        console.error(
            'erro ao coletar com banco de dados', err
        );
        return
    }
    console.log("conectado com banco de dados");
})

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {secure: false}
}))

const authenticateSession = (req, res, next) =>{
    if(!req.session.userId){
        'Acesso Negado, faça login para continuar'
    }
    next()

}

app.post('/login', (req, res) =>{
    const {cpf, senha} = req.body;

    db.query('SELECT * FROM usuarios WHERE cpf = ?', {cpf}, async (err, results) => {
        if (err) return res.status(500).send('Server com erro')
        if (results.length === 0) return res.send(500).send('CPF ou Senha Incorreta')
            const usuario = results[0]
            const senhaCorreta = await bcrypt.compare(
                senha, usuario.senha)
            if (!senhaCorreta) return res.status(500).send(
                'CPF ou senha incorretos'
            )
            req.session.userId = usuario.idUsuario
            console.log('idUsuarios:', usuario.idUsuario);
            res.json({message: 'Login bem sucedido'})
            
    })
})

app.post ('/cadastro', async(req, res) => {
    const {nome, email, cpf, senha, celular, cep, logradouro, bairro, cidade, estado, imagem, Tipos_Usuarios_idTipos_Usuarios} = req.body

    cep = cep.replace(/-/g, '')

    db.query(
            'SELECT cpf FROM usuarios WHERE cpf = ?', [cpf], async(err, results) =>{
                if(err){
                    console.error('Erro ao consultar o CPF:', err);
                    return res.status(500).json({message: 'Erro ao verificar o CPF'})
                }
                if(results.length > 0){
                    return res.status(400).json({message: 'CPF ja cadastrado'})
                }
                const senhacripto = await bcrypt.hash(senha, 10)
                db.query('INSERT INTO usuarios (nome, email, cpf, senha, celular, cep, logradouro, bairro, cidade, estado, imagem, Tipos_Usuarios_idTipos_Usuarios) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)'),
                [nome, email, cpf, senhacripto, celular, cep, logradouro, bairro, cidade, estado, imagem, Tipos_Usuarios_idTipos_Usuarios], (err,results) => {
                    if (err){
                        console.error('Erro ao inserir usuario', err);
                        return res.status(500).json({
                            message: 'Erro ao cadastrar usuario'}
                        )
                    }
                }
            }
    )
})

app.use(express.static('/src'))
app.use(express.static(__dirname + '/src/'))

app.get('/login', (req, res) => {
res.sendFile(__dirname + '/src/login.html')})

app.get('/cadastro', (req, res) => {
res.sendFile(__dirname + '/src/cadastroUsuarios.html')})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(
    `servidor conectado na rota ${PORT}`
))