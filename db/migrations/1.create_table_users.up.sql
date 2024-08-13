CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       name VARCHAR(255) NOT NULL,
                       email VARCHAR(255) NOT NULL UNIQUE,
                       password TEXT NOT NULL,
                       ip_address INET NOT NULL,
                       created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);