const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const ROLES = ['admin', 'analyst'];

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'invalid email'],
    },
    name: { type: String, trim: true, maxlength: 80, default: '' },
    // Only the hash ever touches the database. Plaintext never exists past the
    // request boundary; comparePassword is the only consumer.
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ROLES, default: 'analyst' },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

userSchema.methods.comparePassword = function comparePassword(plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

userSchema.set('toJSON', {
  transform(_doc, ret) {
    delete ret.passwordHash;
    delete ret.__v;
    return ret;
  },
});

const User = mongoose.model('User', userSchema);
User.ROLES = ROLES;
module.exports = User;
