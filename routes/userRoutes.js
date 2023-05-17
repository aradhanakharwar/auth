import express from 'express';
import UserController from '../controllers/userController.js';
import checkUserAuth from '../middleware/auth-middleware.js';

const router = express.Router();

router.use('/changepassword', checkUserAuth)
router.use('/user', checkUserAuth)

// Public Routes
router.post('/register', UserController.userRegistration);
router.post('/login', UserController.userLogin);
router.post('/reset', UserController.sendUserPasswordResetEmail);
router.post('/reset-password/:id/:token', UserController.userPasswordReset);


// Protected Routes
router.post('/changepassword', UserController.changeUserPassword);
router.get('/user', UserController.loggedUser);


export default router;