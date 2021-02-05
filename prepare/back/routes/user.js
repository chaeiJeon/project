const express = require('express');
const bcrypt = require('bcrypt'); // 비밀번호 암호화
const passport = require('passport');

const {User} = require('../models'); // models/index에서 db에 table을 담고 있다. module.exports = db 를 하고 있으니 구조분해할당을 해서 받아오기  


const router = express.Router();
router.post('/login', (req, res, next)=>{
    passport.authenticate('local', (err, user, info)=>{
        if(err){ //첫번째, 두번째, 세번쨰 받아와서 if로 구분
            console.error(err);
            return next(err);
        }
        if(info){//클라이언트 에러가 있다면
            return res.status(403).send(info.reason);
        }
        return req.login(user, async (loginErr)=>{//passport 로그인이 마지막 과정, but 혹시 로그인 과정에서 오류가 있을 수 있으니 if
            if(loginErr){
                console.error(loginErr);
                return next(loginErr);
            }
            return res.status(200).json(user); // 사용자 정보를 front로 넘겨준다
        });
    })(req,res,next);
} 
);//POST /user/login, 로그인 전략 포함(local)
router.post('/', async (req,res,next)=>{ //Post /user/
    try{
        // 중복이 있다면 exUser에 넣기 없으면 NULL
        const exUser = await User.findOne({ // 비동기인지는 공식문서보고 판단
            where : { // 조건
                email : req.body.email, 
            }
        });
        if(exUser){
            return res.status(403).send('이미 사용중인 아이디 입니다');
            // return으로 응답이 한번만 가게한다. 요청이 하나니까 응답도 하나여야함
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 12);
        // 암호화 된 비밀번호 넣기, 해쉬화 하는 것, 12이라는 숫자는 높을 수록 암호화 잘 된다.
        // 너무 높으면 암호화 하는 데 시간을 다 보내게 됨
        await User.create({ //await(순서를 위해)를 넣어야 데이터가 들어간다. await를 쓰려면 async도 함께
            // 비동기 함수를 async await를 이용하여 처리해서 순서를 바로 잡을 수 있게됨
            email : req.body.email, // front saga signupAPI에서 온 data(email, password, nickname)가 req.body
            nickname : req.body.nickname,
            password: hashedPassword,
        });
        res.status(200).send('ok');
        // 200 성공 / 300 리다이렉트 / 400 클라이언트 에러 / 500 서버 에러
    } catch (error){
        console.error(error);
        next(error); // status 500
    }
});

module.exports = router;