import { randomInt } from "crypto";
import nodemailer from "nodemailer";
import dotenv from "dotenv"
dotenv.config()
export const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_PORT === "465",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export const otpStore = new Map();

export const otp = randomInt(100000, 999999).toString();