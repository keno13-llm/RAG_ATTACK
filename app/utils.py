from typing import Any, List

def to_text(resp: Any) -> str:
    """
    Универсально приводит ответ модели к строке.
    """
    if resp is None:
        return ''
    if isinstance(resp, str):
        return resp
    # huggingface pipeline
    if isinstance(resp, list) and resp:
        first = resp[0]
        if isinstance(first, dict) and 'generated_text' in first:
            return first['generated_text']
        if hasattr(first, 'text'):
            return first.text
    # fallback
    return str(resp)

# Карта похожих букв для детекции обфускации
CYRILLIC_LATIN_PAIRS = {
    'а': 'a', 'А': 'A',
    'е': 'e', 'Е': 'E',
    'о': 'o', 'О': 'O',
    'р': 'p', 'Р': 'P',
    'с': 'c', 'С': 'C',
    'у': 'y', 'У': 'Y',
    'х': 'x', 'Х': 'X',
    'і': 'i', 'І': 'I',
    'к': 'k', 'К': 'K',
    'м': 'm', 'М': 'M',
    'т': 't', 'Т': 'T',
    'в': 'b', 'В': 'B',
    'н': 'h', 'Н': 'H'
}

def is_obfuscated(text: str, min_length: int = 6) -> bool:
    """
    True, если в тексте найдены слова с смешанными кириллицей и латиницей,
    либо подозрительными подменами букв.
    """
    obf = find_obfuscated_fragments(text, min_length)
    return bool(obf)

def find_obfuscated_fragments(text: str, min_length: int = 6) -> List[str]:
    """
    Находит все слова в тексте, которые выглядят как смесь латиницы и кириллицы,
    либо содержат похожие буквы-замены из карты CYRILLIC_LATIN_PAIRS.
    """
    import re
    results = []
    words = re.findall(r'\w{' + str(min_length) + ',}', text)
    for w in words:
        cyr = sum('а' <= ch.lower() <= 'я' or ch in CYRILLIC_LATIN_PAIRS for ch in w)
        lat = sum('a' <= ch.lower() <= 'z' or ch in CYRILLIC_LATIN_PAIRS.values() for ch in w)
        if cyr > 0 and lat > 0:
            results.append(w)
        # эвристика: буквы-замены встречаются 2+ раза
        pair_count = sum(1 for ch in w if ch in CYRILLIC_LATIN_PAIRS or ch in CYRILLIC_LATIN_PAIRS.values())
        if pair_count >= 2:
            results.append(w)
    return list(set(results))
