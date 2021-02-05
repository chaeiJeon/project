const express = require('express');
const cors = require('cors');
const session=require('express-session');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const dotenv = require('dotenv');
const postRouter = require('./routes/post');
const userRouter = require('./routes/user');
const db = require('./models');
// models안에 여러 model들 만들기 -> index 합치기 -> app으로 보내기, app이 본체라고 생각
const passportConfig = require('./passport');

dotenv.config(); //소스코드가 털리면 db 비밀번호, 쿠키 문자열 비밀번호도 다 털리게 되니 dotenv사용
const app = express();
db.sequelize.sync()
    .then(()=>{
        console.log('db 연결 성공');
    })
    .catch(console.error);

passportConfig();

app.use(cors({
    origin: '*',
    credentials : false,
}));
//아래 둘 다 프론트에서 보낸 데이터를 req.body안에 넣는 역할
app.use(express.json()); // json 형식을 넣는다
app.use(express.urlencoded({extended : true})); // form submit 했을 때 데이터 처리 역할
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(session({
    saveUninitialized : false,
    resave : false,
    secret : process.env.COOKIE_SECRET,
}));
app.use(passport.initialize());
app.use(passport.session());
app.get('/posts', (req,res)=>{
    res.json([ //json은 보통 data를 의미한다고 보면 된다. res
        {id : 1, content : 'hello'},
    ])
});
app.use('/post',postRouter);//중복되는 것(/post)를 앞으로 뽑아주기
app.use('/user',userRouter);
app.listen(3065, () =>{
    console.log('서버 실행 중');
});