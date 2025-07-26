# app/main.py

import os
import glob
import json
import uuid

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from langchain_core.documents import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter

from app.models import QueryOut, UploadOut
from app.document_loader import extract_text
from app.security import filter_prompt, sanitize_answer, sanity_check, isolate_context
from app.rag import init_app_state
from app.utils import to_text

# ==== НАСТРОЙКИ ====
ATTACK_FILES_DIR = "attack_files"
ATTACK_SCENARIOS_FILE = "attack_scenarios.json"
TEMPLATES_DIR = "templates"

app = FastAPI(title="RAG Prompt Injection Demo")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# In-memory docs: doc_id -> {"text": ..., "meta": ...}
DOCS = {}         # doc_id: {"text": str, "meta": dict, "filename": str}
DOCS_LIST = []    # list of doc_id for ordering (to preserve upload order)

@app.on_event("startup")
def startup_event():
    # Загружаем тестовые встроенные документы (опционально)
    global DOCS, DOCS_LIST
    DOCS.clear()
    DOCS_LIST.clear()
    example_docs = [
        {"text": "secretpersonalmail@local.mail.ru", "meta": {}, "filename": "mail.txt"},
        {"text": "secret_token: tokentokentoken123", "meta": {}, "filename": "token.txt"},
        {"text": "Admin password: 12344321", "meta": {}, "filename": "passwords.txt"},
    ]
    for doc in example_docs:
        doc_id = str(uuid.uuid4())
        DOCS[doc_id] = doc
        DOCS_LIST.append(doc_id)
    app.state.rag = init_app_state([doc["text"] for doc in DOCS.values()])

def load_attack_scenarios():
    """Загрузить описания сценариев атак из attack_scenarios.json"""
    path = os.path.join(ATTACK_SCENARIOS_FILE)
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def list_attack_files_with_scenarios():
    """Вернуть список файлов атак + описание сценария"""
    scenarios = load_attack_scenarios()
    files = []
    for file_path in glob.glob(os.path.join(ATTACK_FILES_DIR, "*")):
        basename = os.path.basename(file_path)
        scenario = scenarios.get(basename, {})
        files.append({
            "file": basename,
            "name": scenario.get("name", basename),
            "scenario": scenario.get("scenario", ""),
        })
    return files

@app.get("/", response_class=HTMLResponse)
def ui(request: Request):
    return templates.TemplateResponse("ui.html", {"request": request})

@app.get("/attack_files")
def attack_files():
    """API для фронта: список доступных атакующих файлов с описанием"""
    return list_attack_files_with_scenarios()

@app.get("/docs")
def list_docs():
    """Список загруженных документов"""
    return [
        {"doc_id": doc_id, "filename": DOCS[doc_id].get("filename", ""), "size": len(DOCS[doc_id]["text"])}
        for doc_id in DOCS_LIST
    ]

@app.post("/upload", response_model=UploadOut)
async def upload_file(file: UploadFile = File(...)):
    """Загрузка пользовательского файла (PDF/DOCX/TXT) в базу RAG"""
    raw_text = extract_text(file)
    doc_id = str(uuid.uuid4())
    DOCS[doc_id] = {
        "text": raw_text,
        "meta": {},  # meta может быть заполнено extract_text при необходимости
        "filename": file.filename
    }
    DOCS_LIST.append(doc_id)
    # Обновить RAG базу с новыми документами
    app.state.rag = init_app_state([DOCS[did]["text"] for did in DOCS_LIST])
    return UploadOut(doc_id=doc_id, size=len(raw_text))

@app.delete("/docs/{doc_id}")
def delete_doc(doc_id: str):
    """Удалить документ из базы"""
    if doc_id not in DOCS:
        raise HTTPException(status_code=404, detail="doc_id не найден")
    del DOCS[doc_id]
    DOCS_LIST.remove(doc_id)
    # Обновить RAG базу
    app.state.rag = init_app_state([DOCS[did]["text"] for did in DOCS_LIST])
    return {"status": "deleted"}

@app.post("/query", response_model=QueryOut)
async def query(q: dict):
    """
    Ожидает:
    {
      "attack_file": "jailbreak.txt" (опционально),
      "defenses": ["isolation", "filter"],  # список
      "prompt": "..."                       # если нет attack_file
      "doc_id": "..." (опционально, строка!)
    }
    """
    state = app.state.rag

    # 1) Получаем исходный prompt/контекст (атакующий файл или пользовательский ввод)
    prompt = ""
    attack_file = q.get("attack_file")
    if attack_file:
        path = os.path.join(ATTACK_FILES_DIR, attack_file)
        if not os.path.exists(path):
            raise HTTPException(status_code=400, detail="Файл атаки не найден")
        ext = attack_file.rsplit('.', 1)[-1].lower()
        if ext in ('txt', 'text'):
            with open(path, encoding="utf-8") as f:
                prompt = f.read()
        elif ext in ('docx', 'pdf'):
            # Мокаем UploadFile для extract_text
            from fastapi import UploadFile
            class DummyUploadFile:
                def __init__(self, filename, content):
                    self.filename = filename
                    from io import BytesIO
                    self.file = BytesIO(content)
            with open(path, "rb") as f:
                content = f.read()
                upload = DummyUploadFile(attack_file, content)
                prompt = extract_text(upload)
        else:
            raise HTTPException(status_code=415, detail="Unsupported attack file type")
    else:
        prompt = q.get("prompt", "").strip()
        if not prompt:
            raise HTTPException(status_code=400, detail="Пустой prompt")

    # 2) Определяем документ/корпус для поиска
    doc_id = q.get("doc_id")
    if doc_id:
        if doc_id not in DOCS:
            raise HTTPException(status_code=404, detail="doc_id не найден")
        doc = DOCS[doc_id]
        raw = [Document(page_content=doc["text"], metadata={"id": doc_id, "filename": doc.get("filename", "")})]
    else:
        # Поиск по всей базе (RAG retrieval)
        raw = state['retriever'].invoke(prompt)
        # ВНИМАНИЕ: здесь контекст может содержать вредоносные вставки из документов

    # 3) Обработка контекста после retrieval: применяем защиты ПОСЛЕ векторизации
    defenses = q.get("defenses", [])
    raw_context = "\n\n".join(d.page_content for d in raw)

    # Для отчёта: что было удалено/заменено в процессе защиты
    isolated_context = None
    context_chunks = []
    for d in raw:
        ctx = d.page_content
        orig_ctx = ctx
        if "isolation" in defenses:
            ctx = isolate_context(ctx)
        if "filter" in defenses:
            ctx, exact, fuzzy = filter_prompt(ctx)
        else:
            exact, fuzzy = [], []
        if "sanitize" in defenses:
            ctx = sanitize_answer(ctx)
        context_chunks.append(ctx)
    final_context = "\n\n".join(context_chunks)
    if "isolation" in defenses:
        isolated_context = final_context

    # 4) Чанкинг для LLM (как и раньше)
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,
        chunk_overlap=200
    )
    chunks = splitter.split_text(final_context)
    selected = chunks[-3:]
    selected_docs = [Document(page_content=c, metadata={}) for c in selected]

    # 5) Составляем финальный prompt для LLM
    prompt_used = prompt

    # 6) Генерируем ответ
    resp = state['chain'].invoke({'input': prompt_used, 'context': selected_docs})
    answer_raw = to_text(resp)

    # 7) Последовательно применяем фильтры/санитизацию к ответу (как safety net)
    answer_sanitized = None
    answer_filtered = None
    exact, fuzzy = [], []

    filtered = answer_raw
    if "filter" in defenses:
        filtered, exact, fuzzy = filter_prompt(filtered)
    if "sanitize" in defenses:
        filtered = sanitize_answer(filtered)
        answer_sanitized = filtered
    answer_filtered = filtered if "filter" in defenses else None

    flags = sanity_check(answer_filtered or answer_sanitized or answer_raw)

    return QueryOut(
        raw_context=raw_context,
        isolated_context=isolated_context,
        prompt_used=prompt_used,
        answer_raw=answer_raw,
        answer_filtered=answer_filtered,
        answer_sanitized=answer_sanitized,
        flags=flags,
        found_exact=exact,
        found_fuzzy=fuzzy,
    )

@app.get("/health")
def health():
    return {"status": "ok"}
