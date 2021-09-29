 require("dotenv/config");
 const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
 const {hash , compare} = require("bcrypt");
 const {v4:uuidv4} = require("uuid");
const users = require("./data");
const { createRefreshToken, createAccessToken, sendRefreshToken, sendAccessToken } = require("./tokens");
const { isAuth } = require("./isAuth");
const verify = require("jsonwebtoken/verify");
var nodemailer = require('nodemailer');


   




    const app = express();
    app.use(cookieParser());
    app.use(express.json());
    app.use(cors());
    app.use(express.urlencoded({extended:true}));
    
     
    app.post("/register" , async (req , res) => {
       
         const { username , password} = req.body;

          try{
           const user = users.find(user => user.username === username);
           
             
           if(user) { throw new Error("Username Taken")};
           const hashedPassword = await hash(password , 10);   
           
                users.push({
                    _id:uuidv4(),
                    username,
                    password:hashedPassword
                })
             res.send({message:"Successfully Registered"});

          }

          catch(err){
             
              res.send({error:err.message});

          }
      


    })
       
      
    app.post("/login" , async (req , res) => {
       
        const { username , password} = req.body;

         try{
          const user = users.find(user => user.username === username);
          
            
          if(!user) { throw new Error("Invalid Email/Password")};


          const hashedPassword = await compare(password , user.password);   
          
            
          if(!hashedPassword) {throw new Error("Invalid Email/Password")}
             
  
           // Creating Our Refresh And Access tokens;
          // Access token should have a shorter lifespan than the refresh token 
          // the refresh token can be stored as a protective cookie on the frontend for persisting login
           
          const accessToken = createAccessToken(user._id);
          const refreshToken = createRefreshToken(user._id);

      
           user.refreshToken = refreshToken;
           // Send The Refresh As A Cookie To The Client And Access As A Normal Response

             sendRefreshToken(res , refreshToken);
             sendAccessToken(req , res , accessToken);
             
              
                
         }

         catch(err){
            
             res.send({error:err.message});

         }

   })

   app.post('/logout' , (req , res) => {

               // Clear The Cookie And Logout The User
               
          res.clearCookie("refreshtoken" , { path:"/refresh_token" } );
          res.send({message:"User Successfully logged out"});

                
   })
     
    
 // Creating A Protected Route For A Validated User
    app.post("/dashboard" , async (req , res) => {
          
        try{
            const userId = isAuth(req); 
            if(userId){
                res.send({data:"You Have Protected Route Privileges"});
            }
        }
        catch(error){
          
             res.send({message:error.message})

        }

    })





  //  Get A New Access Token With A Refresh Token
    app.post("/refresh_token" , (req , res) => {

          const refreshToken = req.cookies.refreshtoken;
                  
        if(!refreshToken) { return  res.send({accessToken:"1"})}
         let payload = null;
        try{
            payload =verify(refreshToken , process.env.REFRESH_TOKEN_SECRET) 

        }
        catch(err){
                 
            res.send({accessToken:"2"})
        }
           
      

        const user = users.find(user => user._id === payload.userId);

           if(!user) { return res.send({accessToken:"4"})} 
              
          if(user.refreshToken !== refreshToken){
              return res.send({accessToken:"3"})
          }
          
          const accessToken = createAccessToken(user._id);
          const newRefreshToken = createRefreshToken(user._id);

          sendRefreshToken(res , newRefreshToken)

          res.send({accessToken})


     
    })


      app.post("/mailer" , (_req , res) => {
             
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              user: process.env.EMAIL,
              pass: process.env.PASSWORD
            }
          });
          
          var mailOptions = {
            from: 'adetayoomotomiwa99@gmail.com',
            to: 'browndev1999@gmail.com',
            subject: 'Sending Email using Node.js',
            text: 'That was easy!'
          };
          

            try{
               
               transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                    throw new Error(error);
            } else {
                 res.send({
                     message:"Email Successfully Sent",
                     info:info.response
                 })
            }
          });


            }

             catch(err){
                  res.send({error:err.message})
            }
          

      })


     
    app.listen(process.env.PORT , () => {
          console.log(`Rocking It On Port ${process.env.PORT}`);
    })