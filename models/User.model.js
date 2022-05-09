const { Schema, model } = require("mongoose");

const userSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
  },
  // favorites: [{ type: Schema.Types.ObjectId, ref: 'Room', default: [] }]
});

const User = model("User", userSchema);

module.exports = User;
