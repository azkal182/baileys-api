// src/controllers/auth.controller.ts
import type { Request, Response, NextFunction } from "express";
import { authService } from "../services/auth.service";
import { registerSchema, loginSchema } from "../schemas/auth.validation";
import { ZodError } from "zod";
import { logger } from "@/utils";

class AuthController {
	async register(req: Request, res: Response, next: NextFunction) {
		try {
			const validatedData = registerSchema.parse(req.body);
			const { user, tokens } = await authService.register(validatedData);

			// Rekomendasi: Kirim refreshToken sebagai HTTP-only cookie
			res.cookie("refreshToken", tokens.refreshToken, {
				httpOnly: true,
				secure: process.env.NODE_ENV === "production", // Gunakan secure di production
				sameSite: "strict", // Lindungi dari CSRF
				expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Contoh 7 hari
			});

			res.cookie("accessToken", tokens.accessToken, {
				httpOnly: true,
				secure: process.env.NODE_ENV === "production", // Gunakan secure di production
				sameSite: "strict", // Lindungi dari CSRF
				expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Contoh 7 hari
			});

			res.status(201).json({
				message: "Pendaftaran berhasil!",
				user: {
					id: user.id,
					name: user.name,
					email: user.email,
				},
				tokens: {
					accessToken: tokens.accessToken,
					apiKey: tokens.apiKey,
				}, // Jangan kirim refreshToken di body JSON
			});
		} catch (error) {
			if (error instanceof ZodError) {
				return res.status(400).json({
					message: "Validasi gagal.",
					errors: error.errors.map((err) => ({
						path: err.path.join("."),
						message: err.message,
					})),
				});
			}
			if (error instanceof Error) {
				return res.status(409).json({ message: error.message });
			}
			next(error);
		}
	}

	async login(req: Request, res: Response, next: NextFunction) {
		try {
			const validatedData = loginSchema.parse(req.body);
			const { user, tokens } = await authService.login(validatedData);

			// Rekomendasi: Kirim refreshToken sebagai HTTP-only cookie
			res.cookie("refreshToken", tokens.refreshToken, {
				httpOnly: true,
				secure: process.env.NODE_ENV === "production",
				sameSite: "strict",
				expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
			});

			res.cookie("accessToken", tokens.accessToken, {
				httpOnly: true,
				secure: process.env.NODE_ENV === "production", // Gunakan secure di production
				sameSite: "strict", // Lindungi dari CSRF
				expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Contoh 7 hari
			});

			res.status(200).json({
				message: "Login berhasil!",
				user: {
					id: user.id,
					name: user.name,
					email: user.email,
				},
				tokens: {
					accessToken: tokens.accessToken,
					refreshToken: tokens.refreshToken,
					expiresIn: tokens.expiresIn,
					// apiKey: tokens.apiKey,
				}, // Jangan kirim refreshToken di body JSON
			});
		} catch (error) {
			if (error instanceof ZodError) {
				return res.status(400).json({
					message: "Validasi gagal.",
					errors: error.errors.map((err) => ({
						path: err.path.join("."),
						message: err.message,
					})),
				});
			}
			if (error instanceof Error) {
				return res.status(401).json({ message: error.message });
			}
			next(error);
		}
	}

	async refreshAccessToken(req: Request, res: Response, next: NextFunction) {
		try {
			// logger.info("refresh token");

			// Ambil refresh token dari cookie ATAU body
			const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

			logger.info(refreshToken);
			if (!refreshToken) {
				return res.status(401).json({ message: "Refresh token tidak tersedia." });
			}

			const newTokens = await authService.refreshAccessToken(refreshToken);
			logger.info(newTokens);

			// Set refreshToken baru ke HTTP-only cookie
			res.cookie("refreshToken", newTokens.refreshToken, {
				httpOnly: true,
				secure: process.env.NODE_ENV === "production",
				sameSite: "strict",
				expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 hari
			});

			res.status(200).json({
				message: "Access token berhasil diperbarui!",
				tokens: {
					accessToken: newTokens.accessToken,
					refreshToken: newTokens.refreshToken,
					expiresIn: newTokens.expiresIn,
				},
			});
		} catch (error) {
			if (error instanceof Error) {
				return res.status(401).json({ message: error.message });
			}
			next(error);
		}
	}

	async getProfile(req: Request, res: Response, next: NextFunction) {
		try {
			if (!req.user || !req.user.id) {
				return res.status(401).json({ message: "Pengguna tidak terautentikasi." });
			}

			const userProfile = await authService.getProfile(req.user.id);

			if (!userProfile) {
				return res.status(404).json({ message: "Profil pengguna tidak ditemukan." });
			}

			res.status(200).json({
				message: "Profil pengguna berhasil diambil.",
				user: userProfile,
			});
		} catch (error) {
			next(error);
		}
	}
}

export const authController = new AuthController();
