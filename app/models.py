from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel

class AttackType(str, Enum):
    none = "none"
    jailbreak = "jailbreak"
    leak = "leak"

class DefenseType(str, Enum):
    none = "none"
    filter = "filter"
    sanitize = "sanitize"
    isolation = "isolation"

class Query(BaseModel):
    prompt: str
    doc_id: Optional[str] = None        # Теперь строка (UUID)
    attack: AttackType = AttackType.none
    defense: DefenseType = DefenseType.none

class QueryOut(BaseModel):
    raw_context: str                    # контекст ДО фильтрации/изоляции
    isolated_context: Optional[str]     # после изоляции (если применялась)
    prompt_used: str
    answer_raw: str                     # ответ ДО фильтрации/санитизации
    answer_filtered: Optional[str]      # после filter_prompt
    answer_sanitized: Optional[str]     # после sanitize_answer
    flags: Dict[str, Any]               # sanity-check флаги
    found_exact: List[str]              # точные совпадения паттернов
    found_fuzzy: List[str]              # нечёткие совпадения паттернов

class UploadOut(BaseModel):
    doc_id: str
    size: int

class DocInfo(BaseModel):
    doc_id: str
    filename: Optional[str] = None
    size: int
