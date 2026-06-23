from fastapi import Depends, FastAPI

app = FastAPI()


def verify_token():
    pass


@app.post("/api/memories/add", dependencies=[Depends(verify_token)])
def add_memory(body: dict):
    return {"status": "ok"}


@app.get("/api/memories/search", dependencies=[Depends(verify_token)])
def search_memories():
    return {"results": []}
