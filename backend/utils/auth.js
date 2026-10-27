import jwt from "jsonwebtoken";

const COOKIE_NAME='token';
const TOKEN_LIFETIME_SECONDS=7*24*60*60;


function cookieOptions(){
       return {
          httpOnly:true,
          secure:process.env.NODE_ENV=='production',
          sameSite:process.env.COOKIE_SAME_SITE || 'lax',
          path:'/'
       };
}

export function createToken(){
    return jwt.sign(
        {id:}
    )
}