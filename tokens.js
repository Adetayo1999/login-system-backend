
  const {sign} = require("jsonwebtoken");


  const createAccessToken = userId => {

     return sign({userId} , process.env.ACCESS_TOKEN_SECRET , {
         expiresIn:'15m'
     });

  }


  
  const createRefreshToken = userId => {

    return sign({userId} , process.env.REFRESH_TOKEN_SECRET , {
        expiresIn:'7d'
    });

 }

 const sendAccessToken = ( req , res , accessToken) => {
   
    res.send({
         accessToken,
          email:req.body.email
    })
      

 }

 const sendRefreshToken = (res , refreshToken) => {
     
    res.cookie("refreshtoken" , refreshToken , {
        path:'/refresh_token',
        httpOnly:true,
        secure: process.env.NODE_ENV === 'production' ? true : false
    })
     
}



 module.exports = {
       createAccessToken,
       createRefreshToken,
       sendAccessToken,
       sendRefreshToken
 }


