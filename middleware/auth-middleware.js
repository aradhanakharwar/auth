import jwt from 'jsonwebtoken';
import userModel from '../models/user.js';


var checkUserAuth = async (req, res, next) => {
    let token;
    const { authorization } = req.headers;
    if (authorization && authorization.startsWith('Bearer')) {
        try {
            // Get Token from Header
            token = authorization.split(' ')[1];

            // Verify Token
            const { userId } = jwt.verify(token, process.env.JWT_SECRET_KEY);

            // Get User from Token
            req.user = await userModel.findById(userId).select('-password');

            next();

        } catch (error) {
            res.send({ "status": "failed", "message": "Unauthorized user." });
        };
    }
    else {
        res.send({ "status": "failed", "message": "Unauthorized user, No Token." });
    };
};

export default checkUserAuth;

// $2b$10$ihtMvuW8SLBnU5yaGEvYiO8wfQuKSwGJIgnQjricj/K/9yzhkhUx6