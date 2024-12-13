
const express = require('express')
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')


require('dotenv').config()

const app = express()

app.use(express.json())

const User = require('./model/User.js');

app.get('/', (req, res) => {
    res.status(201).json({ msg: "bem vindo" })
})



//Private Route
app.get('/user/:id', checktoken, async(req, res)=>{
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({
            msg: "usuario não encontrado"
        })
    }
    res.status(200).json({user})
})


function checktoken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg: "acesso negado!"})
    }

    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()

    }catch(error){
        res.status(400).json({msg: "token inválido"})
    }
}



//register user
app.post('/auth/register', async (req, res)=>{
    const {name, email, password, confirmpassword} = req.body

//validations
    if(!name){
        return res.status(422).json({msg: "o nome é obrigatório"})
    }

    if(!email){
        return res.status(422).json({msg: "o email é obrigatório"})
    }

    if(!password){
        return res.status(422).json({msg: "A senha  é obrigatórioa"})
    } 

    if(password !== confirmpassword){
        return res.status(422).json({msg: "As senhas não conferem!"})
    } 


    //check if user exists
    const userExists = await User.findOne({ email: email})
    if(userExists){
        return res.status(422).json({msg: "Por favor, utilize outro email"})
    }

    const salt= await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password , salt)


    //create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })


    try{
        await user.save()

        res.status(201).json({msg: "usuario criado com suceso!"})

    }catch(error){
        console.log(error)

        res.status(500).json({msg: 'ERRO no SERVIDOR'})
    }
    
})


//Login User
app.post('/auth/login', async(req,res)=>{
    const {email, password} = req.body

    if(!email){
        return res.status(422).json({msg: "o email é obrigatório"})
    }

    if(!password){
        return res.status(422).json({msg: "A senha  é obrigatórioa"})
    } 


    //check if user exists
    const user = await User.findOne({ email: email})
    if(!user){
        return res.status(404).json({msg: "Usuario não encontrado"})
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({msg: 'senha inválida'})
    }


    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        },
        secret,

    )
        res.status(200).json({
            msg: "autenticação realizada com sucesso!", token
        })

    }catch(err){
        console.log(error)

        res.status(500).json({msg: 'ERRO no SERVIDOR'})
    }

})


//credential
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASSWORD


mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.ehh3n.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
.then(() => {
    app.listen(3333)
    console.log('conectado ao banco de dados!')

}).catch((err) => console.log(err))




