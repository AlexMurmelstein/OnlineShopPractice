const express = require('express');
const bcrypt = require('bcryptjs');
const { check, body } = require('express-validator');

const User = require('../models/user');

const authController = require('../controllers/auth');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.get('/reset', authController.getReset);

router.post(
  '/login',
  [
    //Remember: though these two checks are the same as in the "/signup" route,
    //Getting them into constants will fuck up the code and generate errors
    check('email').isEmail().withMessage('please enter a vaild email'),
    body('password', 'please add a pwd longer than 5 chars')
      .isLength({ min: 1 })
      .isAlphanumeric(),
  ],
  authController.postLogin
);

router.post(
  '/signup',
  [
    check('email')
      .isEmail()
      .withMessage('please enter a vaild email')
      .custom((value, { req }) => {
        return User.findOne({ email: value }).then(userDoc => {
          if (userDoc) {
            return Promise.reject('E-mail already exists');
          }
        });
      }),
    body('password', 'please add a pwd longer than 5 chars')
      .isLength({ min: 1 })
      .isAlphanumeric(),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('pwds not equal');
      }
      return true;
    }),
  ],
  authController.postSignup
);

router.post('/logout', authController.postLogout);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;
