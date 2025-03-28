import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import userRouter from "./controllers/user-controller.js";

const app = new Hono();

app.get("/", (c) => {
  return c.text("Hello Hono!");
});

app.use(cors({ origin: "http://localhost:5173", credentials: true }));

app.route("/api/auth/user", userRouter);

serve(
  {
    fetch: app.fetch,
    port: 3030,
  },
  (info) => {
    console.log(`Server is running on http://localhost:${info.port}`);
  }
);
