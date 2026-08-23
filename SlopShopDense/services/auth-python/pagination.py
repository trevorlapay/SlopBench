"""Pagination utilities."""
from dataclasses import dataclass
from typing import List

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


@dataclass
class Page:
    items: List
    page: int
    size: int
    total: int

    @property
    def pages(self) -> int:
        if self.size == 0:
            return 0
        return (self.total + self.size - 1) // self.size

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    def as_dict(self) -> dict:
        return {
            "page": self.page,
            "size": self.size,
            "total": self.total,
            "pages": self.pages,
            "has_next": self.has_next,
            "has_prev": self.has_prev,
        }


def normalize_page_args(page, size) -> tuple:
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE
    size = max(1, min(MAX_PAGE_SIZE, size))
    return page, size


def paginate(all_items: List, page: int, size: int) -> Page:
    page, size = normalize_page_args(page, size)
    start = (page - 1) * size
    window = all_items[start:start + size]
    return Page(items=window, page=page, size=size, total=len(all_items))
