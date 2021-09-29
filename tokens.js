
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
          username:req.body.username
    })
      

 }

 const sendRefreshToken = (res , refreshToken) => {
     
    res.cookie("refreshtoken" , refreshToken , {
        httpOnly:true,
        path:'/refresh_token'
    })
     
}



 module.exports = {
       createAccessToken,
       createRefreshToken,
       sendAccessToken,
       sendRefreshToken
 }

