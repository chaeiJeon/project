// 로그인 전략 !


const passport = require('passport');
const {Strategy : LocalStrategy} = require('passport-local');
// Strategy : LocalStrategy는 Strategy 이름을 LocalStrategy로 바꾸겠다는 의미
const bcrypt = require('bcrypt');
const {User } = require('../models');

module.exports = () =>{
    // 하나는 객체, 하나는 함수
    passport.use(new LocalStrategy({
        usernameField : 'email', //req.body.email 이다
        passwordField : 'password', 

    }, async (email, password, done) => {
        try{ //await는 항상 try로 감싸주기
        const user = await User.findOne({
            where : {
                email //== email : email
            }
        });
        if(!user){
            return done(null, false, { reason : ' 존재하지 않는 사용자입니다! '})
            // 첫번째자리 서버, 두번째자리 성공, 세번째자리 클라이언트 에러(보내는 측 에러)
            // done이 callback 같은 것
        }
        const result = await bcrypt.compare(password, user.password) //입력한 pwd와 db의 pwd가 일치하는지
        if(result){
            return done(null, user); // 로그인 성공이니 두번째자리에 유저의 정보 넣기
        }
        return done(null, false, { reason : '비밀번호가 틀렸습니다'}); // 비밀번호 틀렸을 때
    }catch(error){
        console.error(error);
        return done(error);
    }
    }));

}
