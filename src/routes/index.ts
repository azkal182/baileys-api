import { Router } from "express";
import chatRoutes from "./chats";
import groupRoutes from "./groups";
import messageRoutes from "./messages";
import sessionRoutes from "./sessions";
import contactRoutes from "./contacts";
import auth from "./auth";
import { authenticateToken } from "@/middlewares/auth-middleware";

const router = Router();
router.use("/api/auth", auth);
router.use("/api/sessions", authenticateToken, sessionRoutes);
router.use("/api/:sessionId/chats", authenticateToken, chatRoutes);
router.use("/api/:sessionId/contacts", authenticateToken, contactRoutes);
router.use("/api/:sessionId/groups", authenticateToken, groupRoutes);
router.use("/api/:sessionId/messages", authenticateToken, messageRoutes);

export default router;
