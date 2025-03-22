from fastapi import FastAPI, Request
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI()

# Use TrustedHostMiddleware to get client's real IP
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])


@app.get("/info/client")
async def get_client_ip(request: Request):
    client_ip = request.client.host
    return {"client_ip": client_ip}


@app.get("/info/server")
async def root():
    return {
        "pyinfo": "Python 3.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023, 05:45:37) [MSC v.1934 64 bit (AMD64)] on win32"}


@app.get("/info/database")
async def get_database():
    return {"db": "postgres"}
