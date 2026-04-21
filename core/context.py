from core.context_store import ContextStore
from core.extractor import Extractor


class Context:

    def __init__(self):
        self.store = ContextStore()
        self.extractor = Extractor(self.store)

    def update(self, response, url):
        self.extractor.process(response, url)

    def get(self, key):
        return self.store.get(key)

    def dump(self):
        return self.store.dump()
