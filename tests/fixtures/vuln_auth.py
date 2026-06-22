from fastapi import FastAPI

app = FastAPI()


@app.post("/api/memories/add")
def add_memory(body: dict):
    user_id = body.user_id
    return {"status": "ok"}


@app.get("/api/memories/search")
def search_memories():
    return {"results": []}
