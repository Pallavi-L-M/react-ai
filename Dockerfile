FROM node:22-alpine AS frontend
WORKDIR /web
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY --from=frontend /web/dist ./static
ENV DATABASE_URL=sqlite:////data/react_ai.db FRONTEND_ORIGIN=http://localhost:8000
RUN mkdir -p /data
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
