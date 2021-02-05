const passport = require('passport');
const local = require('./local');
const {User } = require('../models');

module.exports = () =>{
    passport.serializeUser((user, done)=>{ //req.login의 user가 여기 들어간다
        done(user.id); //쿠키랑 묶어줄 id만 저장하는 것

    });
    passport.deserializeUser(async (id, done)=>{
        try{
            const user = await User.findOne({where : {id}});
            done(null, user); //첫번째 인자는 서버에러, 두번째 인자는 유저
        } catch(error){
                console.error(error);
                done(error);
        }
    });
    local();
}