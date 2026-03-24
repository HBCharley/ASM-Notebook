from .db import ENGINE, Base
from . import models  # noqa: F401 — ensure all models are registered


def init_db() -> None:
    Base.metadata.create_all(bind=ENGINE)
