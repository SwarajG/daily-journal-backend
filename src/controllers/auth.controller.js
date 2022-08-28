const httpStatus = require('http-status');
const passport = require('passport');
const catchAsync = require('../utils/catchAsync');
const { authService, userService, tokenService, emailService } = require('../services');

const register = catchAsync(async (req, res) => {
  const user = await userService.createUser(req.body);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ user, tokens });
});

const initGoogleAuth = (req, res, next) => {
  passport.authenticate('google', {
    scope: ['email', 'profile'],
  })(req, res, next);
};

const authViaOauth = async (req, res) => {
  const { _user } = req;
  const { email, id, name, picture } = _user;
  const data = {
    email,
    googleId: id,
    name,
    isEmailVerified: true,
    image: picture,
  };
  const user = await userService.getUserByEmail(email);
  if (user) {
    const token = await tokenService.generateAuthTokens(user);
    res.redirect(`http://localhost:3000/login?jwtToken=${token}`);
  } else {
    const userResponse = await userService.createUser(data);
    const token = await tokenService.generateAuthTokens(userResponse);
    res.redirect(`http://localhost:3000/login?jwtToken=${token}`);
  }
};

const authWithGoogle = async (req, res) => {
  return authViaOauth(req, res, 'google');
};

const registerViaGoogle = async (data) => {
  const user = await userService.createUser(data);
  await tokenService.generateAuthTokens(user);
};

const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.loginUserWithEmailAndPassword(email, password);
  const tokens = await tokenService.generateAuthTokens(user);
  res.send({ user, tokens });
});

const logout = catchAsync(async (req, res) => {
  await authService.logout(req.body.refreshToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const refreshTokens = catchAsync(async (req, res) => {
  const tokens = await authService.refreshAuth(req.body.refreshToken);
  res.send({ ...tokens });
});

const forgotPassword = catchAsync(async (req, res) => {
  const resetPasswordToken = await tokenService.generateResetPasswordToken(req.body.email);
  await emailService.sendResetPasswordEmail(req.body.email, resetPasswordToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const resetPassword = catchAsync(async (req, res) => {
  await authService.resetPassword(req.query.token, req.body.password);
  res.status(httpStatus.NO_CONTENT).send();
});

const sendVerificationEmail = catchAsync(async (req, res) => {
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(req.user);
  await emailService.sendVerificationEmail(req.user.email, verifyEmailToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token);
  res.status(httpStatus.NO_CONTENT).send();
});

module.exports = {
  register,
  registerViaGoogle,
  initGoogleAuth,
  authWithGoogle,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
};
