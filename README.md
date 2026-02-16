# Google Keep Clone MVP

Docker-installable MVP of a Google Keep style notes app.

## Stack
- **Backend:** Node.js + Express + SQLite
- **Frontend:** React + Vite
- **Orchestration:** Docker Compose

## Features
- Notes CRUD (create/read/update/delete)
- Color labels for notes
- Pin / unpin notes
- Archive / unarchive notes
- Checklist items with done/undone toggle
- Search across title, content, tags, checklist text
- Tags per note
- Basic auth: **disabled for now**

## Project Structure
- `backend/` - REST API and SQLite storage
- `frontend/` - React app
- `docker-compose.yml` - full stack local deployment

## Run with Docker
From repository root:

```bash
docker compose up --build
```

Then open:
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:4000`
- Health check: `http://localhost:4000/health`

Stop services:

```bash
docker compose down
```

## API Endpoints
- `GET /notes?archived=true|false&q=term`
- `GET /notes/:id`
- `POST /notes`
- `PUT /notes/:id`
- `DELETE /notes/:id`

## Development (without Docker)
### Backend
```bash
cd backend
npm install
npm run dev
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

If needed, set API URL:
```bash
export VITE_API_URL=http://localhost:4000
```
