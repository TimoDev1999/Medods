CREATE TABLE refresh_tokens (
                                id SERIAL PRIMARY KEY,
                                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                                token_hash TEXT NOT NULL,
                                ip_address INET NOT NULL,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
                                expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);