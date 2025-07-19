// src/types/express/index.d.ts
import type { User } from "@prisma/client"; // Sesuaikan path jika lokasi User model berbeda

// Deklarasikan atau perluas modul 'express-serve-static-core'
// yang digunakan oleh Express untuk tipe Request/Response
declare module "express-serve-static-core" {
	interface Request {
		user?: User; // Tambahkan properti user ke objek Request
	}
}
