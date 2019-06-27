const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authConfig = require('../../config/auth');
const crypto = require('crypto');

const User = require('../models/user');

const router = express.Router();

function generateToken(parmas = {}) {
    return jwt.sign(parmas, authConfig.secret, {
        expiresIn: 86400,
    });
}

router.post('/register', async (req, res) => {
    const { email } = req.body;

    try {
        if(await User.findOne({ email }))
            return res.status(400).send({'message': 'User already exists.'})

        const user = await User.create(req.body);

        user.password = undefined;

        return res.send({ user, token: generateToken({ id: user._id }) });
    } catch (error) {
        res.status(400).send({ error });
    }
});

router.post('/authenticate', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email }).select('+password');

        if(!user)
            return res.status(400).send({'massage': 'User not found'});
            
        if(!await bcrypt.compare(password, user.password))
            return res.status(400).send({'message': 'Invalid password'});

        user.password = undefined;

        return res.send({ user, token: generateToken({ id: user._id }) });
    } catch (error) {
        return res.status(400).send({ error });
    }
});

router.post('/forgot_password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if(!user)
            return res.status(400).send({'massage': 'User not found'});

        const token = crypto.randomBytes(20).toString('hex');

        const now = new Date();
        now.setHours(now.getHours() + 1);

        await User.findByIdAndUpdate(user._id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: now,
            }
        });

        return res.send({ token, now });

    } catch (error) {
        return res.status(400).send({ error });
    }
})

module.exports = app => app.use('/auth', router);