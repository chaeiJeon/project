// table(=model) 만들기
module.exports= (sequelize, DataTypes)=>{
    const Hashtag = sequelize.define('Hashtag', { //MySQL에는 Hashtags(대문자가 소문자가 되고 복수가 된다, sequelize와 mysql간 규칙) 테이블 생성
        //id는 기본적으로 들어있음
        name : {
            type : DataTypes.STRING(20),
            allowNull : false,},
    },{
        charset : 'utf8mb4',
        collate : 'utf8mb4_general_ci', //한글 저장
    });
    Hashtag.associate = (db) =>{
        db.Hashtag.belongsToMany(db.Post, {through : 'PostHashtag'});
    };
    return Hashtag;
}