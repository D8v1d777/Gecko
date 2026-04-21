import httpx


class ContextSession(httpx.AsyncClient):
    """
    A wrapped httpx client that automatically feeds every response
    into the global Context for intelligence gathering.
    """

    def __init__(self, context, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = context

    async def request(self, method, url, **kwargs):
        response = await super().request(method, url, **kwargs)
        # Automatically update context with every request made by any module
        try:
            self.context.update(response, str(url))
        except Exception as e:
            # Silent failure to avoid breaking scans
            pass
        return response
