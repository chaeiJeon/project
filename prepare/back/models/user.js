
// table(=model) 만들기
module.exports= (sequelize, DataTypes)=>{
    const User = sequelize.define('User', { //MySQL에는 users(대문자가 소문자가 되고 복수가 된다, sequelize와 mysql간 규칙) 테이블 생성
        //id는 기본적으로 들어있음
        email : {
            type : DataTypes.STRING(30), // 어떤 데이터가 들어갈지 검사 가능
            // type으로 STRING, NEXT, BOOLEAN, INTEGER, FLOAT, DATETIME...
            allowNull : false, //필수
            unique : true,
        },
        nickname : {
            type : DataTypes.STRING(30),
            allowNull : false, 
        },
        password : {
            type : DataTypes.STRING(100),// 암호화를 하면 길이가 늘어난다
            allowNull : false,

        },
    },{
        charset : 'utf8',
        collate : 'utf8_general_ci', //한글 저장
    });
    User.associate = (db) =>{
        db.User.hasMany(db.Post);//User가 Post를 많이 가질 수 있다
        db.User.hasMany(db.Comment);
        db.User.belongsToMany(db.Post, { through : 'Like', as : 'Liked'}); //User가 게시글에 좋아요 누르는 것
                                                // 중간 테이블 이름을 Like 로 정해줄 수 있다, 정해주면 반대쪽에서도 똑같이 해줘야함
                                                // Liked : 내가 좋아요를 누른 애들
        db.User.belongsToMany(db.User, {through : 'Follow', as : 'Followers', foreignKey : 'FollowingId'});    
        db.User.belongsToMany(db.User, {through : 'Follow', as : 'Followings', foreignKey : 'FollowerId'});    
        // foreignKey로 먼저 찾아야 할 것을 표시한다. 만약 채이의 팔로워를 찾아라, 하면 채이 부터 먼저 찾아야 한다
        // 왜 User, Post 사이 다대다 관계에서는 foreignKey를 사용하지 않는가 ? 
            // : User, Post사이에는 키 이름이 UserId, PostId라서 구별을 하는데 User, User사이에는 UserId, UserId 라서 구분할 수 없다. 그래서 foreignKey로 직접 키 이름을 바꾸어 준다
            // through는 table이름, foreignKey는 column의 이름    

    };      
    return User;
}