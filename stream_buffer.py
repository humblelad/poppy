import copy
import json
import logging
from typing import AsyncGenerator, List, Optional
from security_engine import Vault

logger = logging.getLogger(__name__)


class StreamRehydrator:
    """Swap fake secrets back to real ones inside a streamed SSE response.

    Replacing on the raw wire text does not work. A model streams its answer as
    many small deltas, each framed as its own `data: {...}` event, so a fake that
    spans two deltas is interleaved with JSON framing and never appears as a
    contiguous string:

        data: {"delta":{"text":"AKIAXJPX"}}

        data: {"delta":{"text":"GQIMBCTN"}}

    So events are parsed instead: the decoded delta text is accumulated across
    events, rehydrated there, and re-emitted. Everything else (message_start,
    ping, content_block_stop, ...) passes through untouched, with any pending
    text flushed first so ordering is preserved.
    """

    # Delta payload fields that carry model output, in the order we look for them.
    TEXT_FIELDS = ("text", "thinking", "partial_json")

    def __init__(self, vault: Vault):
        self.vault = vault
        # Escaped forms are longer than their raw counterparts, so size the
        # hold-back window from the pairs actually being searched for.
        self.pairs = vault.rehydration_pairs()
        self.max_fake_len = max((len(f) for f, _ in self.pairs), default=0)
        self.raw = ""                      # incomplete wire text
        self.pending = ""                  # decoded delta text not yet emitted
        self.template: Optional[dict] = None   # event to clone when re-emitting
        self.field: Optional[str] = None       # which delta field it carries

    async def process_stream(self, response_stream: AsyncGenerator[str, None]) -> AsyncGenerator[str, None]:
        if self.max_fake_len == 0:
            # Fast path: nothing was vaulted, so there is nothing to restore.
            async for chunk in response_stream:
                yield chunk
            return

        async for chunk in response_stream:
            self.raw += chunk
            # SSE events are terminated by a blank line.
            while "\n\n" in self.raw:
                block, self.raw = self.raw.split("\n\n", 1)
                for out in self._handle(block):
                    yield out

        for out in self._flush(hold_back=False):
            yield out
        if self.raw:
            yield self.raw
            self.raw = ""

    def _handle(self, block: str) -> List[str]:
        """Route one complete SSE event."""
        data = self._parse(block)
        field = self._delta_field(data)

        if field is None:
            # Not a text-bearing delta. Emit what we are holding, then this event
            # unchanged, so the client sees the original ordering.
            out = self._flush(hold_back=False)
            out.append(block + "\n\n")
            return out

        # Deltas for a different block or field can't be coalesced with what we
        # are holding, so close that group out first.
        if self.template is not None and (
            field != self.field or data.get("index") != self.template.get("index")
        ):
            out = self._flush(hold_back=False)
        else:
            out = []

        self.template = data
        self.field = field
        self.pending += data["delta"][field]
        out.extend(self._flush(hold_back=True))
        return out

    def _parse(self, block: str) -> Optional[dict]:
        for line in block.split("\n"):
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except (ValueError, TypeError):
                    return None
        return None

    def _delta_field(self, data) -> Optional[str]:
        if not isinstance(data, dict):
            return None
        delta = data.get("delta")
        if not isinstance(delta, dict):
            return None
        for name in self.TEXT_FIELDS:
            if isinstance(delta.get(name), str):
                return name
        return None

    def _flush(self, hold_back: bool) -> List[str]:
        """Rehydrate pending text and emit it, optionally keeping a tail back.

        While a run of deltas is still arriving, the last `max_fake_len - 1`
        characters are held: a fake could be half-delivered and completed by the
        next event.
        """
        if not self.pending or self.template is None:
            if not hold_back:
                self.template = self.field = None
            return []

        text = self._rehydrate(self.pending)

        if hold_back:
            cut = max(0, len(text) - (self.max_fake_len - 1))
            emit, self.pending = text[:cut], text[cut:]
        else:
            emit, self.pending = text, ""

        out = [self._event(emit)] if emit else []
        if not hold_back:
            self.template = self.field = None
        return out

    def _rehydrate(self, text: str) -> str:
        for fake, real in self.pairs:
            if fake in text:
                logger.info(f"DEBUG: Rehydrated fake secret '{fake}' back to real secret in stream!")
                text = text.replace(fake, real)
        return text

    def _event(self, text: str) -> str:
        data = copy.deepcopy(self.template)
        data["delta"][self.field] = text
        name = data.get("type", "content_block_delta")
        return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
