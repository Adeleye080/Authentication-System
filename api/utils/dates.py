from datetime import datetime


def add_ordinal_suffix(day) -> str:
    """adds ordinal suffix to the day date"""
    if 10 <= day <= 20:
        suffix = "th"
    else:
        suffix = {1: "str", 2: "nd", 3: "rd"}.get(day % 10, "th")

    return f"{day}{suffix}"


def normalize_date(date: datetime) -> str:
    """
    Convert datetime to normal date string.\n
    e.g '20th January 2025'
    """

    day = date.day
    month = date.strftime("%B")
    year = date.year

    return f"{add_ordinal_suffix(day)} {month} {year}"
