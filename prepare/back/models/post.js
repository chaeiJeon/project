// table(=model) 만들기
module.exports= (sequelize, DataTypes)=>{
    const Post = sequelize.define('Post', { //MySQL에는 Posts(대문자가 소문자가 되고 복수가 된다, sequelize와 mysql간 규칙) 테이블 생성
        //id는 기본적으로 들어있음
        contnet : {
            type : DataTypes.TEXT,
            allowNull : false,
        },
        // as : 'Retweet'를 해주어서
        // PostId => RetweetId 로 바뀐다
    },{
        charset : 'utf8mb4',//mb4는 이모티콘
        collate : 'utf8mb4_general_ci', //한글 저장
    });
    Post.associate = (db) =>{
        db.Post.belongsTo(db.User); //Post는 User에게 속해 있다
        db.Post.belongsToMany(db.Hashtag, {through : 'PostHashtag'}); // 다대다 관계, 게시글에 해시태그 많이 달 수 있고, 해시태그를 눌렀을 때 여러 게시글이 나올 수 있기 때문에
        db.Post.hasMany(db.Comment);
        db.Post.hasMany(db.Image);
        db.Post.belongsToMany(db.User, { through : 'Like', as : 'Likers'});
        //위 db.Post.belongsTo와 헷갈릴 수 있으니 as로 구별해준다. as : 좋아요를 누른 사람들
        db.Post.belongsTo(db.Post, { as : 'Retweet'});
        // 1번 게시글을 2,3,4번 게시글이 리트윗 했다고 한다.(2,3,4게시글이 1번 게시글이 리트윗되어 나온 복사물) 
        // 그럼 일대다관계
    };
    return Post;
}