const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const { validationResult } = require('express-validator');

const User = require('../models/user');
const errorHandler = require('../util/error');

const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_user: "Didn't bother to open acc",
      api_key: "Didn't bother to open acc",
    },
  })
);

exports.getLogin = (req, res, next) => {
  let errMsg = req.flash('error');
  if (errMsg.length > 0) {
    errMsg = errMsg[0];
  } else {
    errMsg = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: errMsg,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: '',
    },
    validationErrors: [],
  });
};

exports.getSignup = (req, res, next) => {
  let errMsg = req.flash('error');
  if (errMsg.length > 0) {
    errMsg = errMsg[0];
  } else {
    errMsg = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: errMsg,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: '',
    },
    validationErrors: [],
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);

  //Form reused
  const renderAuth = (errMsg, valErr) => {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errMsg,
      oldInput: {
        email: email,
        password: password,
      },
      validationErrors: valErr,
    });
  };
  //

  if (!errors.isEmpty()) {
    return renderAuth(errors.array()[0].msg, errors.array());
  }

  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        return renderAuth('Invalid email', [{ param: 'email' }]);
      }
      bcrypt.compare(password, user.password).then(doMatch => {
        if (doMatch) {
          req.session.isLoggedIn = true;
          req.session.user = user;
          return req.session.save(err => {
            console.log(err);
            res.redirect('/');
          });
        }
        return renderAuth('Invalid password', [{ param: 'password' }]);
      });
    })
    .catch(err => {
      console.log(err);
      res.redirect('/login');
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword,
      },
      validationErrors: errors.array(),
    });
  }

  //promise chain will always run to the end, so either return nothings at the end of each promise
  //OR nest promises like here
  bcrypt
    .hash(password, 1)
    .then(hashedPassword => {
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] },
      });
      //Remember that "user" is a NEW mongoose template
      return user.save();
    })
    .then(savedUser => {
      if (savedUser) {
        res.redirect('/login');
        //We don't care about this op, so we won't add a then block
        return transporter.sendMail({
          to: email,
          from: 'mymail',
          subject: 'something',
          html: '<h1>Something</h1>',
        });
      }
    })
    .catch(err => {
      return next(errorHandler(err));
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req, res, next) => {
  let errMsg = req.flash('error');
  if (errMsg.length > 0) {
    errMsg = errMsg[0];
  } else {
    errMsg = null;
  }
  res.render('auth/reset', {
    path: '/signup',
    pageTitle: 'Reset password',
    errorMessage: errMsg,
  });
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      res.redirect('/reset');
    }
    const token = buffer.toString('hex');
    console.log('TOKEN: ', token);
    User.findOne({ email: req.body.email })
      .then(user => {
        if (!user) {
          req.flash('error', 'No account with that email found!');
          return res.redirect('/reset');
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 36000000;
        return user.save();
      })
      .then(result => {
        res.redirect('/');
        return transporter.sendMail({
          to: req.body.email,
          from: 'mymail',
          subject: 'pwd reset',
          html: `<h1>pwd reset, confirm at <a href="http://localhost:3000/reset/${token}"></a></h1>`,
        });
      })
      .catch(err => {
        return next(errorHandler(err));
      });
  });
};

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  let errMsg = req.flash('error');
  if (errMsg.length > 0) {
    errMsg = errMsg[0];
  } else {
    errMsg = null;
  }
  User.findOne({
    resetToken: token,
    resetTokenExpiration: { $gt: Date.now() },
  })
    .then(user => {
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'New Password',
        errorMessage: errMsg,
        userId: user._id.toString(),
        passwordToken: token,
      });
    })
    .catch(err => {
      req.flash('error', 'No matching user or token expired');
    });
};

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken,
    resetTokenExpiration: { $gt: Date.now() },
    _id: userId,
  })
    .then(user => {
      resetUser = user;
      return bcrypt.hash(newPassword, 1);
    })
    .then(hashedPassword => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then(result => {
      res.redirect('/login');
    })
    .catch(err => {
      return next(errorHandler(err));
    });
};
