import mongoose from "./index.js";

const validateEmail = (e) => {
  var emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
  return emailPattern.test(e);
};

const userSchema = new mongoose.Schema(
  {
    userName: {
      type: String,
      requried: [true, "UserName required"],
    },

    email: {
      type: String,
      reqired: [true, "Email is reqired"],
      validate: validateEmail,
    },

    password: {
      type: String,
      required: [true, "password is required"],
    },

    randomString: {
      type: String,
    },
  },
  {
    versionKey: false,
  }
);

const userModel = mongoose.model("users", userSchema);

export default userModel;
