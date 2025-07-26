import os
import tempfile
from io import BytesIO
from fastapi import HTTPException, UploadFile
from PyPDF2 import PdfReader
import docx

from app.utils import find_obfuscated_fragments

def extract_text(file: UploadFile) -> str:
    """
    Извлекает текст из файла (PDF, DOCX, TXT).
    Также анализирует на наличие обфускации и вредоносных метаданных.
    """
    content = file.file.read()
    if not content:
        raise HTTPException(status_code=400, detail="File is empty")
    name = file.filename or ''
    ext = name.rsplit('.', 1)[-1].lower()

    # Всё, что извлекли из файла
    raw_text = ""
    meta_text = ""

    if ext == 'pdf':
        reader = PdfReader(BytesIO(content))
        # 1. Извлекаем основной текст
        raw_text = '\n'.join(page.extract_text() or '' for page in reader.pages)
        # 2. Проверяем вредоносные метаданные
        meta_text = extract_pdf_metadata(reader)

    elif ext in ('docx', 'doc'):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.' + ext)
        try:
            tmp.write(content)
            tmp.close()
            doc = docx.Document(tmp.name)
            # 1. Основной текст
            raw_text = '\n'.join(p.text for p in doc.paragraphs)
            # 2. Метаданные — автор, заголовок, сноски
            meta_text = extract_docx_metadata(doc)
        finally:
            os.unlink(tmp.name)

    elif ext in ('txt', 'text'):
        raw_text = content.decode('utf-8', errors='ignore')
        meta_text = ""

    else:
        raise HTTPException(status_code=415, detail="Unsupported file type")

    # Анализируем обфускацию (основной текст и метаданные)
    obfuscated = find_obfuscated_fragments(raw_text)
    meta_obfuscated = find_obfuscated_fragments(meta_text) if meta_text else []

    # Можно возвращать структуру для фронта:
    # return {
    #     "text": raw_text,
    #     "meta": meta_text,
    #     "obfuscated": obfuscated,
    #     "meta_obfuscated": meta_obfuscated
    # }
    # Но для RAG возвращаем просто текст (+мета внизу для анализа)
    return raw_text + ("\n\n[Вредоносные метаданные:]\n" + meta_text if meta_text else "")

def extract_pdf_metadata(reader) -> str:
    """
    Извлекает подозрительные метаданные из PDF (автор, producer, subject).
    """
    meta = reader.metadata
    results = []
    keys = ['/Author', '/Title', '/Subject', '/Producer', '/Creator']
    for k in keys:
        v = meta.get(k, "")
        if v and any(x in v.lower() for x in [
            "ignore previous instructions", "system prompt", "developer", "metadata", "alt", "role"
        ]):
            results.append(f"{k}: {v}")
    # Можно добавить извлечение аннотаций
    if hasattr(reader, "annotations"):
        for ann in reader.annotations:
            if ann and any(x in ann.lower() for x in [
                "ignore previous instructions", "system prompt"
            ]):
                results.append(f"annotation: {ann}")
    return "\n".join(results)

def extract_docx_metadata(doc) -> str:
    """
    Извлекает метаданные и сноски из DOCX.
    """
    results = []
    # Core properties
    core_props = doc.core_properties
    for k in ('author', 'title', 'subject', 'comments'):
        v = getattr(core_props, k, None)
        if v and any(x in str(v).lower() for x in [
            "ignore previous instructions", "system prompt", "developer", "metadata", "alt", "role"
        ]):
            results.append(f"{k}: {v}")
    # Можно добавить парсинг сносок и скрытых полей через lxml или docx2txt
    return "\n".join(results)
