// src/schemas/auth.validation.ts
import { z } from "zod";

export const registerSchema = z.object({
	name: z.string().min(3, "Nama minimal 3 karakter").max(255, "Nama maksimal 255 karakter"),
	email: z.string().email("Format email tidak valid").max(255, "Email maksimal 255 karakter"),
	password: z
		.string()
		.min(6, "Password minimal 6 karakter")
		.max(255, "Password maksimal 255 karakter"),
});

export const loginSchema = z.object({
	email: z.string().email("Format email tidak valid"),
	password: z.string().min(1, "Password tidak boleh kosong"),
});

export const apiKeySchema = z.object({
	apiKey: z
		.string()
		.min(32, "API Key minimal 32 karakter")
		.max(64, "API Key maksimal 64 karakter"),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type ApiKeyInput = z.infer<typeof apiKeySchema>;
