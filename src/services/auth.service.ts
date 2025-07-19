// src/services/auth.service.ts
import { prisma } from "@/config/database";
import type { RegisterInput, LoginInput } from "@/schemas/auth.validation";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import env from "@/config/env";
import type { User } from "@prisma/client";
import { ulid } from "ulid";
import ms from "ms";
import { logger } from "@/utils";

interface AuthTokens {
	accessToken: string;
	refreshToken: string;
	apiKey?: string;
	expiresIn: number;
}

class AuthService {
	// Helper function untuk generate tokens
	private generateTokens(userId: string, apiKey: string): AuthTokens {
		// Melakukan type assertion untuk expiresIn agar sesuai dengan tipe yang diharapkan oleh jsonwebtoken
		const accessToken = jwt.sign({ userId }, env.JWT_SECRET, {
			expiresIn: env.ACCESS_TOKEN_EXPIRATION as jwt.SignOptions["expiresIn"],
		});

		// Melakukan type assertion untuk expiresIn agar sesuai dengan tipe yang diharapkan oleh jsonwebtoken
		const refreshToken = jwt.sign({ userId, apiKey }, env.JWT_REFRESH_SECRET, {
			expiresIn: env.REFRESH_TOKEN_EXPIRATION as jwt.SignOptions["expiresIn"],
		});

		const expiresIn = ms(env.ACCESS_TOKEN_EXPIRATION) / 1000;

		return { accessToken, refreshToken, apiKey, expiresIn };
	}

	async register(data: RegisterInput): Promise<{ user: User; tokens: AuthTokens }> {
		const existingUser = await prisma.user.findUnique({
			where: { email: data.email },
		});

		if (existingUser) {
			throw new Error("Email sudah terdaftar.");
		}

		const hashedPassword = await bcrypt.hash(data.password, 10);
		const newApiKey = ulid();

		const user = await prisma.user.create({
			data: {
				name: data.name,
				email: data.email,
				password: hashedPassword,
				token: newApiKey,
			},
		});

		const tokens = this.generateTokens(user.id, newApiKey);

		// Simpan refreshToken ke database
		await prisma.user.update({
			where: { id: user.id },
			data: { refreshToken: tokens.refreshToken },
		});

		return { user, tokens };
	}

	async login(data: LoginInput): Promise<{ user: User; tokens: AuthTokens }> {
		const user = await prisma.user.findUnique({
			where: { email: data.email },
		});

		if (!user) {
			throw new Error("Kredensial tidak valid.");
		}

		const isPasswordValid = await bcrypt.compare(data.password, user.password);

		if (!isPasswordValid) {
			throw new Error("Kredensial tidak valid.");
		}

		const apiKey = user.token || ulid();
		if (!user.token) {
			await prisma.user.update({
				where: { id: user.id },
				data: { token: apiKey },
			});
		}

		const tokens = this.generateTokens(user.id, apiKey);

		// Simpan refreshToken yang baru ke database
		await prisma.user.update({
			where: { id: user.id },
			data: { refreshToken: tokens.refreshToken },
		});

		console.log(tokens);

		return { user, tokens };
	}

	async refreshAccessToken(refreshToken: string): Promise<AuthTokens> {
		try {
			console.log({ refreshToken });
			// Memverifikasi refresh token
			const decoded = jwt.verify(refreshToken, env.JWT_REFRESH_SECRET) as {
				userId: string;
				apiKey: string;
			};

			console.log({ decoded });

			const user = await prisma.user.findUnique({
				where: { id: decoded.userId },
			});

			// Pastikan user ada dan refresh token yang dikirim sesuai dengan yang tersimpan di DB
			if (!user || user.refreshToken !== refreshToken) {
				throw new Error("Invalid refresh token.");
			}

			// Generate accessToken baru dan refreshToken baru
			const newTokens = this.generateTokens(user.id, user.token || ulid());

			// Perbarui refreshToken di database
			await prisma.user.update({
				where: { id: user.id },
				data: { refreshToken: newTokens.refreshToken },
			});

			return newTokens;
		} catch (error) {
			// Tangani berbagai jenis kesalahan verifikasi token
			if (error instanceof jwt.TokenExpiredError) {
				throw new Error("Refresh token kedaluwarsa.");
			}
			if (error instanceof jwt.JsonWebTokenError) {
				throw new Error("Refresh token tidak valid.");
			}
			logger.error(error);
			throw new Error("Gagal memperbarui token.");
		}
	}

	async getProfile(userId: string): Promise<Partial<User> | null> {
		const user = await prisma.user.findUnique({
			where: { id: userId },
			select: {
				id: true,
				name: true,
				email: true,
				token: true,
			},
		});
		return user;
	}
}

export const authService = new AuthService();
