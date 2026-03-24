FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend .
ARG VITE_API_BASE=
ARG VITE_API_PREFIX=/api/v1
ARG VITE_GOOGLE_CLIENT_ID=
ENV VITE_API_BASE=$VITE_API_BASE
ENV VITE_API_PREFIX=$VITE_API_PREFIX
ENV VITE_GOOGLE_CLIENT_ID=$VITE_GOOGLE_CLIENT_ID
RUN npm run build

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    ASM_FRONTEND_DIST=/app/dist

WORKDIR /app

COPY pyproject.toml poetry.lock requirements.txt alembic.ini /app/
COPY alembic /app/alembic
COPY asm_notebook /app/asm_notebook
COPY api_main.py db.py models.py init_db.py cli.py /app/
COPY scripts /app/scripts
COPY --from=frontend-build /app/frontend/dist /app/dist

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

EXPOSE 8080

CMD ["sh", "-c", "alembic upgrade head && uvicorn asm_notebook.api_main:app --host 0.0.0.0 --port ${PORT:-8080}"]
