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

    @property
    def start_index(self) -> int:
        """1-based index of the first item on this page."""
        return 0 if not self.items else (self.page - 1) * self.size + 1

    @property
    def end_index(self) -> int:
        """1-based index of the last item on this page."""
        return (self.page - 1) * self.size + len(self.items)

    def describe(self) -> str:
        """The "showing 21-40 of 137" line the listing views render."""
        if not self.items:
            return "no results"
        return "showing %d-%d of %d" % (self.start_index, self.end_index, self.total)


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


def page_window(current: int, pages: int, span: int = 2):
    """Page numbers to render around the current one, clamped to the range."""
    if pages <= 0:
        return []
    lo = max(1, current - span)
    hi = min(pages, current + span)
    return list(range(lo, hi + 1))


def offset_for(page, size) -> int:
    """Row offset for a page, after both arguments have been normalised."""
    page, size = normalize_page_args(page, size)
    return (page - 1) * size


def empty_page(size: int = DEFAULT_PAGE_SIZE) -> Page:
    """A well-formed empty result, so callers never special-case None."""
    return Page(items=[], page=1, size=size, total=0)
