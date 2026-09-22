import os
from dotenv import load_dotenv

load_dotenv(override=True)

APP_NAME = os.getenv("APP_NAME", "Project Crime Lens")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./crimelens.db")

USE_NEO4J = os.getenv("USE_NEO4J", "false").lower() == "true"
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", os.getenv("LLM_API_KEY", ""))
OPENAI_MODEL = os.getenv("OPENAI_MODEL", os.getenv("LLM_MODEL", "gpt-4.1-mini"))
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", os.getenv("LLM_BASE_URL", ""))
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

RAG_TOP_K = int(os.getenv("RAG_TOP_K", "4"))
RAG_CHUNK_SIZE = int(os.getenv("RAG_CHUNK_SIZE", "500"))
RAG_CHUNK_OVERLAP = int(os.getenv("RAG_CHUNK_OVERLAP", "100"))

