// table(=model) 만들기
module.exports= (sequelize, DataTypes)=>{
    const Comment = sequelize.define('Comment', { //MySQL에는 Comments(대문자가 소문자가 되고 복수가 된다, sequelize와 mysql간 규칙) 테이블 생성
        //id는 기본적으로 들어있음
        contnet : {
            type : DataTypes.TEXT,
            allowNull : false,
        },
        //belognsTo 하면 실제  column이
        //UserID : 1 
        //PostId : 3 이처럼 생긴다
    },
    {
        charset : 'utf8mb4',//em4는 이모티콘
        collate : 'utf8mb4_general_ci', //한글 저장
    });
    Comment.associate = (db) =>{
        db.Comment.belongsTo(db.User);
        db.Comment.belongsTo(db.Post);
    };
    return Comment;
}