FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY asm_notebook/ ./asm_notebook/

RUN mkdir -p /data

EXPOSE 8000

ENV ASM_DB_PATH=/data/asm_notebook.sqlite3
ENV ASM_CACHE_DIR=/data/asm_cache

CMD ["uvicorn", "asm_notebook.api_main:app", "--host", "0.0.0.0", "--port", "8000"]
