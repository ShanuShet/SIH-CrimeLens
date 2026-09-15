from pydantic import BaseModel
from typing import Optional

class ChatRequest(BaseModel):
    question: str

class PathRequest(BaseModel):
    source: str
    target: str
    max_hops: int = 5
