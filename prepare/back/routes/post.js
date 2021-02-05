const express = require('express'); //node에서는 import대신 require

const router = express.Router();
router.post('/',(req,res)=>{ //실제로는 POST /post
    res.json( //json은 보통 data를 의미한다고 보면 된다. res
        {id : 1, content : 'hello'},
    )
});
router.delete('/',(req,res)=>{ //실제로는 DELETE /post
    res.json( //json은 보통 data를 의미한다고 보면 된다. res
        {id : 1, content : 'hello'},)
});

module.exports = router;// expore default는 module.exports