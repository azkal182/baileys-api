import express from "express";
import type { Application, Request, Response } from "express";
import cors from "cors";
import routes from "@/routes";
import cookieParser from "cookie-parser"; // Import ini

export class ExpressServer {
	private app: Application;

	constructor() {
		this.app = express();
		this.setupMiddleware();
		this.setupRoutes();
	}

	private setupMiddleware() {
		this.app.use(cors());
		// this.app.use(
		// 	cors({
		// 		origin: "http://localhost:3000", // Ganti dengan URL frontend Next.js Anda
		// 		credentials: true, // Izinkan pengiriman cookie (termasuk refreshToken)
		// 		methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Metode HTTP yang diizinkan
		// 		allowedHeaders: ["Content-Type", "Authorization"], // Header yang diizinkan
		// 	}),
		// );
		this.app.use(express.json());
		this.app.use(cookieParser());
	}

	private setupRoutes() {
		this.app.use("/", routes);

		this.app.all("*", (_: Request, res: Response) =>
			res.status(404).json({ error: "URL not found" }),
		);
	}

	public getApp(): Application {
		return this.app;
	}
}
