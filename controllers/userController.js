import userModel from '../models/user.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import transporter from '../config/emailConfig.js';


class UserController {

    static userRegistration = async (req, res) => {
        const { name, email, password, confirm_password, tc } = req.body;
        const user = await userModel.findOne({ email: email });
        if (user) {
            res.send({ "status": "failed", "message": "Email already exists." });
        } else {
            if (name && name && password && confirm_password && tc) {
                if (password === confirm_password) {
                    try {
                        const salt = await bcrypt.genSalt(10);
                        const hashPassowrd = await bcrypt.hash(password, salt);
                        const doc = new userModel({
                            name: name,
                            email: email,
                            password: hashPassowrd,
                            tc: tc
                        });
                        await doc.save();

                        // Generate JWT Token
                        const saved_user = await userModel.findOne({ email: email });
                        const token = jwt.sign({ userId: saved_user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' })
                        res.status(201).send({ "status": "success", "message": "Registration success.", 'token': token });

                    } catch (error) {
                        console.log(error);
                        res.send({ "status": "failed", "message": "Unable to register." });
                    }
                } else {
                    res.send({ "status": "failed", "message": "Password and confirm password doesn't match." });
                };

            } else {
                res.send({ "status": "failed", "message": "All fields are required." });
            };
        };
    };


    // User Login
    static userLogin = async (req, res) => {
        try {
            const { email, password } = req.body;
            if (email && password) {
                const findEmail = await userModel.findOne({ email: email });
                if (findEmail != null) {
                    const matchPassword = await bcrypt.compare(password, findEmail.password);
                    if (findEmail && matchPassword) {

                        // Generate JWT Token
                        const token = jwt.sign({ userId: findEmail._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' });
                        res.send({ "status": "failed", "message": "Login success.", result: findEmail, "token": token });
                    } else {
                        res.send({ "status": "failed", "message": "Email or password is not valid." });
                    };
                } else {
                    res.send({ "status": "failed", "message": "You are not a registered user." });
                };
            } else {
                res.send({ "status": "failed", "message": "All fields are required." });
            };
        } catch (error) {
            console.log(error);
            res.send({ "status": "failed", "message": "Unable to login." });
        };
    };

    // Change User Password

    static changeUserPassword = async (req, res) => {
        const { password, confirm_password } = req.body;
        if (password && confirm_password) {
            if (password !== confirm_password) {
                res.send({ "status": "failed", "message": "Password and confirm password doesn't match." });
            } else {
                const salt = await bcrypt.genSalt(10);
                const newHashPassword = await bcrypt.hash(password, salt)
                await userModel.findByIdAndUpdate(req.user._id, {
                    $set: { password: newHashPassword }
                })
                res.status(201).send({ "status": "success", "message": "Password changed successfully." });
            }
        } else {
            res.send({ "status": "failed", "message": "All fields are required." });
        }
    }

    static loggedUser = (req, res) => {
        res.send(req.user);
    };

    static sendUserPasswordResetEmail = async (req, res) => {
        const { email } = req.body;
        if (email) {
            const user = await userModel.findOne({ email: email });
            console.log('line 103', user);
            if (user) {
                const secret = await user._id + process.env.JWT_SECRET_KEY;
                const token = jwt.sign({ userId: user._id }, secret, { expiresIn: '10m' });
                const link = ` http://localhost:3000/api/user/reset/${user._id}/${token}`;
                console.log(link);
                let info = await transporter.sendMail({
                    from: process.env.EMAIL_FROM,
                    to: user.email,
                    subject: "GeekShop - Password Reset Link",
                    html: `<a href=${link}>Click here</a> to Reset Your Password.`
                })
                res.send({ status: 'success', message: 'Password reset email send successfully.', "info": info });
            } else {
                res.send({ "status": "failed", "message": "Invalid email." });
            }
        } else {
            res.send({ "status": "failed", "message": "Email field are required." });
        };
    };

    static userPasswordReset = async (req, res) => {
        const { password, confirm_password } = req.body;
        const { id, token } = req.params;
        const user = await userModel.findById(id);
        const new_secret = await user._id + process.env.JWT_SECRET_KEY;
        try {
            jwt.verify(token, new_secret);
            if (password && confirm_password) {
                if (password !== confirm_password) {
                    res.send({ "status": "failed", "message": "Password and confirm password doesn't match." });
                } else {
                    const salt = await bcrypt.genSalt(10);
                    const newHashPassword = await bcrypt.hash(password, salt);
                    await userModel.findByIdAndUpdate(user._id, {
                        $set: { password: newHashPassword }
                    });
                    res.status(201).send({ "status": "success", "message": "Password reset successfully." });
                }
            } else {
                res.send({ "status": "failed", "message": "All fields are required." });
            }
        } catch (error) {
            res.send({ "status": "failed", "message": "Invalid Token." });
        };
    };
};

export default UserController;