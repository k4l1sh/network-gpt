from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import endpoints


app = FastAPI(docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.post("/api/networkgpt/")(endpoints.networkgpt)
app.get("/api/streamlogs/")(endpoints.stream_logs)