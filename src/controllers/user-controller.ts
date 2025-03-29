import dotenv from "dotenv";
import { google } from "googleapis";
import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import jwt from "jsonwebtoken";
import { authorizationUrl, oAuth2Client } from "../libs/google-auth.js";
import { otpStore } from "../libs/index.js";
import { prisma } from "../libs/prisma.js";
import {
  getUserByEmailRepository,
  identifierUserRepository,
} from "../repositories/user-repository.js";
import {
  authentificationUserService,
  checkUserService,
  getUserService,
  registerUserService,
} from "../services/user-service.js";
import type { UserForm } from "../utils/user.js";
dotenv.config();

const userRouter = new Hono();

userRouter.post("/register", async (c) => {
  const body = (await c.req.json()) as UserForm;
  try {
    await registerUserService(body);

    return c.json({ message: "Register Success!", error: false }, 200);
  } catch (error) {
    return c.json(
      { message: "Register Failed!", error: (error as Error).message },
      200
    );
  }
});

userRouter.post("/login", async (c) => {
  const { identifier, password } = await c.req.json();

  try {
    const { token } = await checkUserService(
      identifier as string,
      password as string
    );

    setCookie(c, "user_token", token, {
      path: "/",
      sameSite: "Lax",
      httpOnly: true,
      secure: !!process.env.NODE_ENV,
      maxAge: 60 * 60 * 24 * 7,
    });

    return c.json({ message: "login Success!", token, error: false }, 200);
  } catch (error) {
    return c.json(
      { message: "login Failed!", error: (error as Error).message },
      200
    );
  }
});

userRouter.get("/get-user", async (c) => {
  try {
    const { authorization } = await c.req.header();
    const user = await getUserService(authorization);
    return c.json({ message: "success to get user data!", data: user }, 200);
  } catch (error) {
    return c.json({
      message: "failed to get user data!",
      error: (error as Error).message,
    });
  }
});

userRouter.post("/authentification-user", async (c) => {
  try {
    const { identifier, otp } = await c.req.json();
    if (!identifier || !otp) {
      throw new Error("Email or Username and OTP are required");
    }

    const user = await identifierUserRepository(identifier);

    if (!user) {
      throw new Error("Invalid Email or Username!");
    }

    const storedOtp = otpStore.get(user.email);
    if (!storedOtp || storedOtp !== otp) {
      throw new Error("OTP Tidak valid");
    }

    await authentificationUserService(user.email, otp);

    return c.json(
      { message: `Selamat ${user.email} akunmu sudah aktif!`, error: null },
      200
    );
  } catch (error) {
    return c.json({
      message: "failed to get user data!",
      error: (error as Error).message,
    });
  }
});

userRouter.get("/get-user-session", async (c) => {
  try {
    const cookie = getCookie(c, "user_token");
    if (!cookie) throw new Error("Cookie not found");
    return c.json({ cookie, error: false }, 200);
  } catch (error) {
    return c.json({ cookie: null, error: true }, 404);
  }
});
userRouter.post("/logout", async (c) => {
  deleteCookie(c, "user_token");
  return c.json({ message: "Success to logout", error: false }, 200);
});

//? LOGIN GOOGLE!

userRouter.get("/google", async (c) => {
  return c.redirect(authorizationUrl);
});

//? CALLBACK LOGIN

userRouter.get("/google/callback", async (c) => {
  try {
    const code = await c.req.query("code"); // Directly get query parameter
    if (!code) {
      throw new Error("Code are required!");
    }
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    const OAuth2 = google.oauth2({
      auth: oAuth2Client,
      version: "v2",
    });

    const { data } = await OAuth2.userinfo.get();

    if (!data) {
      throw new Error("Cannot getting user data!");
    }

    const { email, name } = data;

    if (!email || !name) {
      throw new Error("Email dan Username tidak didapatkan");
    }
    let user = await getUserByEmailRepository(email);

    if (!user) {
      user = await prisma.user.create({
        data: { email, username: name },
      });
    }

    const { id } = user;

    if (!user.isAuthenticated) {
      await prisma.user.update({
        where: { id },
        data: { isAuthenticated: true },
      });
    }

    const token = jwt.sign({ id }, process.env.SECRET_KEY || "".toString(), {
      expiresIn: "30m",
    });
    setCookie(c, "user_token", token, {
      path: "/",
      httpOnly: true,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: "Lax",
      secure: !!process.env.NODE_ENV,
    });

    return c.redirect(process.env.FRONTEND_URL || "http://localhost:5173");
  } catch (error) {
    return c.json(
      {
        message: (error as Error).message || "Google Auth Failed",
        error: true,
      },
      400
    );
  }
});

export default userRouter;
