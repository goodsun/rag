--
-- PostgreSQL database dump
--

\restrict 10zNgNOC2mRErYXW5ekzch3PTQBghOj6BGLSZM5XngLp2d4CSGSlFBwVfJ2ZtSs

-- Dumped from database version 17.8 (Homebrew)
-- Dumped by pg_dump version 17.8 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: chunks; Type: TABLE; Schema: rag; Owner: -
--

CREATE TABLE rag.chunks (
    id text NOT NULL,
    collection text NOT NULL,
    doc_key text NOT NULL,
    content text NOT NULL,
    embedding public.vector(768),
    title text,
    url text,
    date date,
    chunk_index integer,
    total integer,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: collections; Type: TABLE; Schema: rag; Owner: -
--

CREATE TABLE rag.collections (
    name text NOT NULL,
    description text,
    origin text,
    embed_model text DEFAULT 'text-embedding-004'::text NOT NULL,
    embed_dim integer DEFAULT 768 NOT NULL,
    chunk_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: documents; Type: VIEW; Schema: rag; Owner: -
--

CREATE VIEW rag.documents AS
 SELECT collection,
    doc_key,
    max(title) AS title,
    max(url) AS url,
    max(date) AS date,
    count(*) AS chunk_count,
    max(total) AS total,
    min(created_at) AS created_at,
    max(updated_at) AS updated_at
   FROM rag.chunks
  GROUP BY collection, doc_key;


--
-- Name: audit_log; Type: TABLE; Schema: shared; Owner: -
--

CREATE TABLE shared.audit_log (
    id bigint NOT NULL,
    user_id integer,
    username text NOT NULL,
    action text NOT NULL,
    target text,
    detail jsonb,
    ip_address text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: shared; Owner: -
--

CREATE SEQUENCE shared.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: shared; Owner: -
--

ALTER SEQUENCE shared.audit_log_id_seq OWNED BY shared.audit_log.id;


--
-- Name: login_attempts; Type: TABLE; Schema: shared; Owner: -
--

CREATE TABLE shared.login_attempts (
    id integer NOT NULL,
    username text NOT NULL,
    ip_address text,
    success boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: login_attempts_id_seq; Type: SEQUENCE; Schema: shared; Owner: -
--

CREATE SEQUENCE shared.login_attempts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: login_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: shared; Owner: -
--

ALTER SEQUENCE shared.login_attempts_id_seq OWNED BY shared.login_attempts.id;


--
-- Name: sessions; Type: TABLE; Schema: shared; Owner: -
--

CREATE TABLE shared.sessions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    user_id integer NOT NULL,
    username text NOT NULL,
    session_version integer NOT NULL,
    ip_address text,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '7 days'::interval) NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: shared; Owner: -
--

CREATE TABLE shared.users (
    id integer NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    role text DEFAULT 'user'::text NOT NULL,
    groups jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    session_version integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: shared; Owner: -
--

CREATE SEQUENCE shared.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: shared; Owner: -
--

ALTER SEQUENCE shared.users_id_seq OWNED BY shared.users.id;


--
-- Name: audit_log id; Type: DEFAULT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.audit_log ALTER COLUMN id SET DEFAULT nextval('shared.audit_log_id_seq'::regclass);


--
-- Name: login_attempts id; Type: DEFAULT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.login_attempts ALTER COLUMN id SET DEFAULT nextval('shared.login_attempts_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.users ALTER COLUMN id SET DEFAULT nextval('shared.users_id_seq'::regclass);


--
-- Name: chunks chunks_pkey; Type: CONSTRAINT; Schema: rag; Owner: -
--

ALTER TABLE ONLY rag.chunks
    ADD CONSTRAINT chunks_pkey PRIMARY KEY (id);


--
-- Name: collections collections_pkey; Type: CONSTRAINT; Schema: rag; Owner: -
--

ALTER TABLE ONLY rag.collections
    ADD CONSTRAINT collections_pkey PRIMARY KEY (name);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: login_attempts login_attempts_pkey; Type: CONSTRAINT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.login_attempts
    ADD CONSTRAINT login_attempts_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: chunks_collection_idx; Type: INDEX; Schema: rag; Owner: -
--

CREATE INDEX chunks_collection_idx ON rag.chunks USING btree (collection);


--
-- Name: chunks_date_idx; Type: INDEX; Schema: rag; Owner: -
--

CREATE INDEX chunks_date_idx ON rag.chunks USING btree (date DESC NULLS LAST);


--
-- Name: chunks_doc_key_idx; Type: INDEX; Schema: rag; Owner: -
--

CREATE INDEX chunks_doc_key_idx ON rag.chunks USING btree (collection, doc_key);


--
-- Name: chunks_embedding_hnsw; Type: INDEX; Schema: rag; Owner: -
--

CREATE INDEX chunks_embedding_hnsw ON rag.chunks USING hnsw (embedding public.vector_cosine_ops);


--
-- Name: chunks_metadata_gin; Type: INDEX; Schema: rag; Owner: -
--

CREATE INDEX chunks_metadata_gin ON rag.chunks USING gin (metadata);


--
-- Name: login_attempts_username_idx; Type: INDEX; Schema: shared; Owner: -
--

CREATE INDEX login_attempts_username_idx ON shared.login_attempts USING btree (username, created_at DESC);


--
-- Name: sessions_expires_idx; Type: INDEX; Schema: shared; Owner: -
--

CREATE INDEX sessions_expires_idx ON shared.sessions USING btree (expires_at);


--
-- Name: chunks chunks_sync_count; Type: TRIGGER; Schema: rag; Owner: -
--

CREATE TRIGGER chunks_sync_count AFTER INSERT OR DELETE ON rag.chunks FOR EACH ROW EXECUTE FUNCTION rag.sync_collection_chunk_count();


--
-- Name: chunks chunks_updated_at; Type: TRIGGER; Schema: rag; Owner: -
--

CREATE TRIGGER chunks_updated_at BEFORE UPDATE ON rag.chunks FOR EACH ROW EXECUTE FUNCTION shared.set_updated_at();


--
-- Name: users users_updated_at; Type: TRIGGER; Schema: shared; Owner: -
--

CREATE TRIGGER users_updated_at BEFORE UPDATE ON shared.users FOR EACH ROW EXECUTE FUNCTION shared.set_updated_at();


--
-- Name: chunks chunks_collection_fkey; Type: FK CONSTRAINT; Schema: rag; Owner: -
--

ALTER TABLE ONLY rag.chunks
    ADD CONSTRAINT chunks_collection_fkey FOREIGN KEY (collection) REFERENCES rag.collections(name) ON DELETE CASCADE;


--
-- Name: audit_log audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.audit_log
    ADD CONSTRAINT audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES shared.users(id) ON DELETE SET NULL;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: shared; Owner: -
--

ALTER TABLE ONLY shared.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES shared.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict 10zNgNOC2mRErYXW5ekzch3PTQBghOj6BGLSZM5XngLp2d4CSGSlFBwVfJ2ZtSs

