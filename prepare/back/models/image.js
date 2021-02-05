// table(=model) 만들기
module.exports= (sequelize, DataTypes)=>{
    const Image = sequelize.define('Image', { //MySQL에는 Comments(대문자가 소문자가 되고 복수가 된다, sequelize와 mysql간 규칙) 테이블 생성
        //id는 기본적으로 들어있음
        src : {
            type : DataTypes.STRING(200),
            allowNull : false,},
    },{
        charset : 'utf8',
        collate : 'utf8_general_ci', //한글 저장
    });
    Image.associate = (db) =>{
        db.Image.belongsTo(db.Post);
    };
    return Image;
}