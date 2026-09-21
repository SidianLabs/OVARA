import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import * as schema from "./schema";

const connectionString = process.env.DATABASE_URL || "postgres://ovara:ovara@localhost:5432/ovara_control";

const client = postgres(connectionString, { max: 20 });
export const db = drizzle(client, { schema });
export type DB = typeof db;
