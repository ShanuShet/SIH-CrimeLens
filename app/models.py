from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from datetime import datetime
from .database import Base


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True)

    key = Column(
        String(255),
        unique=True,
        index=True
    )

    label = Column(
        String(100),
        nullable=False
    )

    name = Column(
        String(255),
        nullable=False
    )

    risk = Column(
        Float,
        default=0.0
    )

    # Optional reference/profile image
    image_path = Column(
        String(500),
        nullable=True
    )


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(Integer, primary_key=True)

    source = Column(
        String(255),
        index=True
    )

    target = Column(
        String(255),
        index=True
    )

    relation = Column(
        String(100)
    )

    timestamp = Column(
        String(100),
        default=""
    )

    amount = Column(
        Float,
        nullable=True
    )


class Case(Base):
    __tablename__ = "cases"

    id = Column(
        Integer,
        primary_key=True
    )

    title = Column(
        String(255)
    )

    status = Column(
        String(50),
        default="Pending"
    )

    risk = Column(
        String(50),
        default="Medium"
    )

    description = Column(
        Text,
        default=""
    )


class Document(Base):
    __tablename__ = "documents"

    id = Column(
        Integer,
        primary_key=True
    )

    filename = Column(
        String(255)
    )

    doc_type = Column(
        String(50),
        default="OTHER"
    )

    data_category = Column(
        String(30),
        default="UNSTRUCTURED"
    )

    file_extension = Column(
        String(20),
        default=""
    )

    file_size = Column(
        Integer,
        default=0
    )

    extraction_method = Column(
        String(100),
        default=""
    )

    content = Column(
        Text,
        default=""
    )

    structured_preview = Column(
        Text,
        default=""
    )

    status = Column(
        String(50),
        default="INGESTED"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(500), nullable=False)
    role = Column(String(50), default="Investigator")
    active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    username = Column(String(120), default="system")
    role = Column(String(50), default="system")
    action = Column(String(120), nullable=False)
    resource = Column(String(255), default="")
    detail = Column(Text, default="")
    ip_address = Column(String(100), default="unknown")
    created_at = Column(DateTime, default=datetime.utcnow)


class BlockchainBlock(Base):
    __tablename__ = "blockchain_blocks"

    id = Column(Integer, primary_key=True)
    block_index = Column(Integer, unique=True, index=True, nullable=False)
    event_type = Column(String(120), nullable=False)
    payload = Column(Text, default="")
    previous_hash = Column(String(128), default="GENESIS")
    block_hash = Column(String(128), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class EvidenceIntegrity(Base):
    __tablename__ = "evidence_integrity"

    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, unique=True, index=True, nullable=False)
    sha256 = Column(String(64), nullable=False)
    file_size = Column(Integer, default=0)
    stored_path = Column(String(500), default="")
    verified_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(30), default="VERIFIED")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True)
    event_type = Column(String(120), nullable=False)
    severity = Column(String(30), default="INFO")
    username = Column(String(120), default="")
    detail = Column(Text, default="")
    ip_address = Column(String(100), default="unknown")
    created_at = Column(DateTime, default=datetime.utcnow)
