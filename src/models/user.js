const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    lowercase: true,
    validate(value) {
      if (!validator.isEmail(value)) {
        throw new Error('Email is Invalid');
      }
    },
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    trim: true,
    validate(value) {
      if (value.toLowerCase().includes('password')) {
        throw new Error('Password cannot contain "password"');
      }
    },
  },
  age: {
    type: Number,
    default: 0,
    validate(value) {
      if (value < 0) {
        throw new Error('Age must be a postive number');
      }
    },
  },
  tokens: [
    {
      token: {
        type: String,
        required: true,
      },
    },
  ],
});
userSchema.statics.findByCredentails = async (email, password) => {
  const user = await User.findOne({ email });
  if (!user) {
    throw new Error('Unable to Login');
  }
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) {
    throw new Error('Unable to Login');
  }
  return user;
};

userSchema.methods.generateToken = async function () {
  const user = this;
  const token = await jwt.sign({ _id: user.id.toString() }, 'jwttoken');
  user.tokens = user.tokens.concat({ token });
  await user.save();
  return token;
};

userSchema.pre('save', async function (next) {
  const user = this;
  if (user.isModified('password'))
    user.password = await bcrypt.hash(user.password, 8);
  next();
});
const User = mongoose.model('User', userSchema);

module.exports = User;
