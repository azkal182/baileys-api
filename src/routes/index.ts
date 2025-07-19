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
router.use("/:sessionId/chats", authenticateToken, chatRoutes);
router.use("/:sessionId/contacts", authenticateToken, contactRoutes);
router.use("/:sessionId/groups", authenticateToken, groupRoutes);
router.use("/:sessionId/messages", authenticateToken, messageRoutes);

export default router;
