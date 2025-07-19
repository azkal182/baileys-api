// src/middlewares/auth-middleware.ts
import { prisma } from "@/config/database";
import env from "@/config/env";
import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

interface JwtPayload {
	userId: string;
}

const authenticateToken = async (req: Request, res: Response, next: NextFunction) => {
	let token: string | null = null;
	let source: "authorization" | "x-api-key" | "cookie" | null = null;

	// 1. Coba dari header Authorization: Bearer <token>
	const authHeader = req.headers["authorization"];
	if (authHeader?.startsWith("Bearer ")) {
		token = authHeader.split(" ")[1];
		source = "authorization";
	}

	// 2. Coba dari x-api-key
	if (!token && req.headers["x-api-key"]) {
		token = Array.isArray(req.headers["x-api-key"])
			? req.headers["x-api-key"][0]
			: req.headers["x-api-key"];
		source = "x-api-key";
	}

	// 3. Coba dari cookie accessToken
	if (!token && req.cookies?.accessToken) {
		token = req.cookies.accessToken;
		source = "cookie";
	}

	if (!token) {
		return res.status(401).json({ message: "Akses ditolak. Token tidak disediakan." });
	}

	try {
		// Jika dari Bearer atau Cookie, asumsikan JWT
		if (source === "authorization" || source === "cookie") {
			if (!env.JWT_SECRET) {
				console.error("JWT_SECRET tidak didefinisikan.");
				return res.status(500).json({ message: "Konfigurasi server tidak lengkap." });
			}

			const decoded = jwt.verify(token, env.JWT_SECRET) as JwtPayload;

			const user = await prisma.user.findUnique({
				where: { id: decoded.userId },
			});

			if (!user) {
				return res
					.status(403)
					.json({ message: "Token tidak valid atau pengguna tidak ditemukan." });
			}

			req.user = user;
			return next();
		}

		// Jika dari x-api-key
		if (source === "x-api-key") {
			const user = await prisma.user.findFirst({
				where: { token: token },
			});

			if (!user) {
				return res
					.status(403)
					.json({ message: "API Key tidak valid atau pengguna tidak ditemukan." });
			}

			req.user = user;
			return next();
		}

		// Fallback jika source tidak dikenali (tidak seharusnya terjadi)
		return res.status(401).json({ message: "Metode autentikasi tidak didukung." });
	} catch (error) {
		console.error("Autentikasi gagal:", error);

		if (error instanceof jwt.TokenExpiredError) {
			return res.status(401).json({ message: "Token JWT telah kedaluwarsa." });
		}

		if (error instanceof jwt.JsonWebTokenError) {
			return res.status(403).json({ message: "Token JWT tidak valid." });
		}

		return res.status(403).json({ message: "Token atau API Key tidak valid." });
	}
};

export { authenticateToken };
