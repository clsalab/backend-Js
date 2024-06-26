const router = require('express').Router();
const User = requiere('../../models/nosql/users');
const bcrypt = requiere('bcryptjs')

// POST /api/users/register
router.post('/register', async (req, res) => {
try{
    req.body.password = bcrypt.hashSync(req.body.password, 10)
  const user = await User.create(req.body);
  res.json(user);
} catch (error) {
    res.json({error: error.message});
}
});

// POST /api/user/login
router.post('/login', async (req, res) => {
    //Comprobar si el mail existe
    const user = await User.findOne ({email: req.body.email});
    if (!user) {
        return res.json({error: 'Error en email/contraseña'});
    }
    const eq = bcrypt.compareSync(req.body.password, user.password);

    if (!eq) {
        return res.json({error: 'Error en email/contraseña'});
    }
    res.json({success: 'Login correcto'});
})



module.exports = router;