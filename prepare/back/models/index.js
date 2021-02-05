const Sequelize = require('sequelize');
const env = process.env.NODE_ENV || 'development'; //환경변수 설정 지금은 기본값으로 development
const config = require('../config/config')[env]; // config에 env를 붙인것, 개발모드로 config 시키려고 
const db = {};

const sequelize = new Sequelize(config.database, config.username, config.password, config); 
//sequelize가 node와 mysql과 연결시켜줌

db.Comment = require('./comment')(sequelize, Sequelize); //모델이 Sequelize에 등록이 된다
db.Hashtag = require('./hashtag')(sequelize, Sequelize);
db.Image = require('./image')(sequelize, Sequelize);
db.Post = require('./post')(sequelize, Sequelize);
db.User = require('./user')(sequelize, Sequelize);

Object.keys(db).forEach(modelName => { // associate 안 실행해주는 것, 관계를 연결해주는 것
  if (db[modelName].associate) {
    db[modelName].associate(db);
  }
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
