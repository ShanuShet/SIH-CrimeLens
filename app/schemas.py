from pydantic import BaseModel
from typing import Optional


class ChatRequest(BaseModel):
    question: str
    case_id: Optional[int] = None


class PathRequest(BaseModel):
    source: str
    target: str
    max_hops: int = 5
    case_id: Optional[int] = None