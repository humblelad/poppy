import gzip
import logging
import zlib
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
import httpx

from security_engine import SecurityEngine
from stream_buffer import StreamRehydrator

logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PoppyProxy")

app = FastAPI(title="Poppy Local: AI Privacy Proxy")
security_engine = SecurityEngine()
http_client = httpx.AsyncClient(base_url="https://api.anthropic.com")

@app.on_event("shutdown")
async def shutdown_event():
    await http_client.aclose()

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    # logger.info(f"Intercepted request to /{path}")
    
    # Extract headers, dropping 'host' and 'content-length' so httpx sets them correctly
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    # Read and decode the body
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8") if body_bytes else ""
    
    # Sanitize payload. `last_hits` records exactly which rule fired on this request,
    # so the log reflects real matches rather than being inferred from the shared vault.
    sanitized_body = security_engine.sanitize_body(body_str)

    if security_engine.last_hits:
        logger.info("Payload contained secrets! Vaulted and swapped with semantic fakes.")
        for rule_name, real_secret in security_engine.last_hits:
            fake_secret = security_engine.vault.reverse_mapping.get(real_secret, "?")
            # logger.info(f"DEBUG: [{rule_name}] Swapped '{real_secret}' -> '{fake_secret}' before sending to LLM")
    
    # Build forward request
    req = http_client.build_request(
        method=request.method,
        url=f"/{path}",
        headers=headers,
        content=sanitized_body.encode("utf-8") if sanitized_body else None,
        params=request.query_params
    )
    
    # Send request with streaming enabled
    response = await http_client.send(req, stream=True)

    # Copy headers except those that might conflict
    resp_headers = dict(response.headers)
    resp_headers.pop("content-encoding", None)
    resp_headers.pop("content-length", None)
    
    content_type = response.headers.get("content-type", "")
    is_sse = "text/event-stream" in content_type
    
    if is_sse:
        
        # In this MVP, vault is shared/global, though ideally it should be request-scoped 
        # or TTL-based for isolation in a multi-user environment.
        rehydrator = StreamRehydrator(security_engine.vault)
        
        async def stream_generator():
            try:
                # `aiter_text()` handles the decoding of bytes from httpx
                async for chunk in rehydrator.process_stream(response.aiter_text()):
                    yield chunk.encode("utf-8")
            finally:
                await response.aclose()
                
        return StreamingResponse(
            stream_generator(), 
            status_code=response.status_code, 
            headers=resp_headers
        )
    else:
        # Non-streaming response: read fully and rehydrate
        try:
            await response.aread()
            resp_text = response.text
            
            rehydrated = False
            for fake_secret, real_secret in security_engine.vault.rehydration_pairs():
                if fake_secret in resp_text:
                    resp_text = resp_text.replace(fake_secret, real_secret)
                    rehydrated = True
                    
            if rehydrated:
                
                logger.info(f"DEBUG: Successfully swapped fake secrets back to real ones!")
                    
            return StreamingResponse(
                iter([resp_text.encode("utf-8")]), 
                status_code=response.status_code,
                headers=resp_headers
            )
        finally:
            await response.aclose()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
