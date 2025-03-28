import { prisma } from "../libs/prisma.js";
import type { UserForm } from "../utils/user.js";

export const registerUserRepository = async (data: UserForm) => {
  const user = await prisma.user.create({ data });
  return user;
};

export const getUserByEmailRepository = async (email: string) => {
  const user = await prisma.user.findFirst({ where: { email } });
  return user;
};
export const getUserByUsernameRepository = async (username: string) => {
  const user = await prisma.user.findFirst({ where: { username } });
  return user;
};

export const getUserByIdRepository = async (id: string) => {
  const user = await prisma.user.findFirst({ where: { id } });
  return user;
};

export const identifierUserRepository = async (identifier: string) => {
  const user = await prisma.user.findFirst({
    where: { OR: [{ username: identifier }, { email: identifier }] },
  });
  return user;
};

export const authentificationUserRepository = async (
  email: string,
  otp: string
) => {
  const user = await prisma.user.update({
    where: { email: email },
    data: {
      isAuthenticated: true,
      authenticationCode: otp,
    },
  });
  return user;
};
