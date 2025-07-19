// src/routes/auth.route.ts
import { Router } from "express";
import { authController } from "../controllers/auth.controller"; // Path diubah
import { authenticateToken } from "@/middlewares/auth-middleware";

const authRouter = Router();

authRouter.post("/register", authController.register);
authRouter.post("/login", authController.login);
authRouter.post("/refresh-token", authController.refreshAccessToken);
authRouter.get("/profile", authenticateToken, authController.getProfile);

export default authRouter;
