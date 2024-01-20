import bcrypt from "bcryptjs";

const hashPassword = async (password) => {
  let salt = await bcrypt.genSalt(Number(process.env.SALT_ROUNDS));
  let hash = await bcrypt.hash(password, salt);
  return hash;
};

const hashcompare = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

export default {
  hashcompare,
  hashPassword,
};
