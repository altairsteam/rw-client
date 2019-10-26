from datetime import datetime

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def now():
    return datetime.now()


def format_date(date):
    return date.strftime(DATE_FORMAT)


def minutes_to_seconds(minutes):
    return minutes * 60
