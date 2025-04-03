import { compareSync, hashSync } from "bcrypt-ts";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { otp, otpStore, transporter } from "../libs/index.js";
import {
  authentificationUserRepository,
  getUserByEmailRepository,
  getUserByIdRepository,
  getUserByUsernameRepository,
  identifierUserRepository,
  registerUserRepository,
} from "../repositories/user-repository.js";
import type { UserForm } from "../utils/user.js";

export const registerUserService = async (data: UserForm) => {
  const usernameExist = await getUserByUsernameRepository(data.username);
  if (usernameExist) {
    throw new Error("Username already used!");
  }
  const emailExist = await getUserByEmailRepository(data.email);
  if (emailExist) {
    throw new Error("Email already used!");
  }
  if (!data.password) {
    throw new Error("Password harus diisi minimal 6 karakter");
  }

  const hashedPassword = hashSync(data.password, 12);

  data.password = hashedPassword;

  const user = await registerUserRepository(data);
  otpStore.set(user.email, otp);

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: "Your OTP Code",
    text: `Your OTP code for Candra Social is: ${otp}`,
  });
  return user;
};

export const checkUserService = async (
  identifier: string,
  password: string
) => {
  const user = await identifierUserRepository(identifier);
  if (!user) {
    throw new Error("Invalid Email or Username");
  }

  if (!user.password) {
    throw new Error(
      "Anda telah mendaftar tanpa menggunakan password,\nsilahkan masuk menggunakan google atau github!"
    );
  }

  const validatePassword = compareSync(password, user.password);

  if (!validatePassword) {
    throw new Error("Invalid Password");
  }

  if (!user.authenticationCode || !user.isAuthenticated) {
    otpStore.set(user.email, otp);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Your OTP Code",
      text: `Your OTP code for Candra Social is: ${otp}`,
    });
    throw new Error("user not authenticated");
  }

  const { id } = user;

  const token = jwt.sign({ id }, process.env.SECRET_KEY || "".toString(), {
    expiresIn: "1h",
  });

  return { token };
};

export const getUserService = async (token: string) => {
  if (!token) {
    throw new Error("You are not authorized!");
  }

  const decodeToken = jwt.verify(
    token,
    process.env.SECRET_KEY || "".toString()
  ) as JwtPayload;

  const user = await getUserByIdRepository(
    decodeToken?.id as unknown as string
  );
  return user;
};

export const authentificationUserService = async (
  email: string,
  otp: string
) => {
  if (!email || !otp) {
    throw new Error("Butuh email dan authentification Code");
  }

  const user = await authentificationUserRepository(email, otp);
  return user;
};
