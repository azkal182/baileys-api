// import { type EventsType } from "@/types/websocket";
// import env from "@/config/env";
// import { Server as SocketIOServer } from "socket.io";
// import type http from "http";

// interface SocketData {
// 	session_id: string;
// }

// export class SocketServer {
// 	private io: SocketIOServer;
// 	private clients: Map<string, Set<string>> = new Map();

// 	constructor(httpServer: http.Server) {
// 		this.io = new SocketIOServer(httpServer, {
// 			cors: {
// 				origin: "*",
// 				methods: ["GET", "POST"],
// 			},
// 		});
// 		this.setupConnectionHandler();
// 	}

// 	private setupConnectionHandler() {
// 		this.io.use((socket, next) => {
// 			const token = socket.handshake.auth.token
// 				? socket.handshake.auth.token
// 				: socket.handshake.headers.token;
// 			if (!token || token !== env.API_KEY) {
// 				return next(new Error("Invalid API key"));
// 			}
// 			next();
// 		});

// 		this.io.on("connection", (socket) => {
// 			const { session_id } = socket.handshake.query as unknown as SocketData;

// 			if (!session_id) {
// 				console.log(`Invalid connection attempt: session_id=${session_id}`);
// 				socket.disconnect(true);
// 				return;
// 			}

// 			this.addClient(session_id, socket.id);
// 			socket.join(session_id);

// 			console.log(`New Socket.IO connection: session_id=${session_id}`);
// 			socket.emit("connected", { session_id });

// 			socket.on("disconnect", () => {
// 				this.removeClient(session_id, socket.id);
// 				console.log(`Socket disconnected: session_id=${session_id}`);
// 			});
// 		});
// 	}

// 	private addClient(session_id: string, socketId: string) {
// 		if (!this.clients.has(session_id)) {
// 			this.clients.set(session_id, new Set());
// 		}
// 		this.clients.get(session_id)!.add(socketId);
// 	}

// 	private removeClient(session_id: string, socketId: string) {
// 		const clientSet = this.clients.get(session_id);
// 		if (clientSet) {
// 			clientSet.delete(socketId);
// 			if (clientSet.size === 0) {
// 				this.clients.delete(session_id);
// 			}
// 		}
// 	}

// 	public emitEvent(event: EventsType, session_id: string, data: unknown) {
// 		console.log(`Emitting event ${event} to session ${session_id}`);

// 		this.io.to(session_id).emit(event, { event, session_id, data });
// 	}

// 	public getConnectedClients(session_id: string): number {
// 		return this.clients.get(session_id)?.size || 0;
// 	}
// }

import { type EventsType } from "@/types/websocket";
import env from "@/config/env";
import { Server as SocketIOServer } from "socket.io";
import type http from "http";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { prisma } from "@/config/database"; // Menambahkan Prisma untuk verifikasi user berdasarkan JWT

interface SocketData {
	session_id: string;
}

export class SocketServer {
	private io: SocketIOServer;
	private clients: Map<string, Set<string>> = new Map();

	constructor(httpServer: http.Server) {
		this.io = new SocketIOServer(httpServer, {
			cors: {
				origin: "*",
				methods: ["GET", "POST"],
			},
		});
		this.setupConnectionHandler();
	}

	private setupConnectionHandler() {
		// Middleware untuk autentikasi token JWT
		this.io.use(async (socket, next) => {
			// Ambil token dari handshake
			const token = socket.handshake.auth.token || socket.handshake.headers.token;

			if (!token) {
				return next(new Error("Token tidak disediakan"));
			}

			try {
				// Verifikasi token JWT
				if (!env.JWT_SECRET) {
					console.error("JWT_SECRET tidak didefinisikan.");
					return next(new Error("Konfigurasi server tidak lengkap"));
				}

				const decoded = jwt.verify(token, env.JWT_SECRET) as JwtPayload;

				// Cari pengguna berdasarkan userId yang ada pada token
				const user = await prisma.user.findUnique({
					where: { id: decoded.userId },
				});

				if (!user) {
					return next(new Error("Pengguna tidak ditemukan atau token tidak valid"));
				}

				// Menyimpan informasi pengguna pada socket
				// eslint-disable-next-line @typescript-eslint/ban-ts-comment
				// @ts-ignore
				socket.user = user;
				next(); // lanjutkan ke event koneksi
			} catch (error) {
				console.error("Autentikasi WebSocket gagal:", error);
				return next(new Error("Token tidak valid"));
			}
		});

		this.io.on("connection", (socket) => {
			const { session_id } = socket.handshake.query as unknown as SocketData;

			if (!session_id) {
				console.log(`Invalid connection attempt: session_id=${session_id}`);
				socket.disconnect(true);
				return;
			}

			this.addClient(session_id, socket.id);
			socket.join(session_id);

			console.log(`New Socket.IO connection: session_id=${session_id}`);
			socket.emit("connected", { session_id });

			socket.on("disconnect", () => {
				this.removeClient(session_id, socket.id);
				console.log(`Socket disconnected: session_id=${session_id}`);
			});
		});
	}

	private addClient(session_id: string, socketId: string) {
		if (!this.clients.has(session_id)) {
			this.clients.set(session_id, new Set());
		}
		this.clients.get(session_id)!.add(socketId);
	}

	private removeClient(session_id: string, socketId: string) {
		const clientSet = this.clients.get(session_id);
		if (clientSet) {
			clientSet.delete(socketId);
			if (clientSet.size === 0) {
				this.clients.delete(session_id);
			}
		}
	}

	public emitEvent(event: EventsType, session_id: string, data: unknown) {
		console.log(`Emitting event ${event} to session ${session_id}`);

		this.io.to(session_id).emit(event, { event, session_id, data });
	}

	public getConnectedClients(session_id: string): number {
		return this.clients.get(session_id)?.size || 0;
	}
}
