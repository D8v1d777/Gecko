class Config(dict):
    """
    Simplified configuration class that behaves like a dictionary
    but supports dotted access if needed (optional).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get(self, key, default=None):
        return super().get(key, default)
