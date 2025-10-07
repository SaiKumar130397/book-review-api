from fastapi import FastAPI

app = FastAPI()

@app.get("/api/healthcheck")
async def healthcheck():
    return {"status": "200", "message": "OK"}
    