import threading

from collections.abc import Callable, Hashable


class Timer:
    """
    A thread-safe and restartable timer that executes a given callback function after a specified interval.

    When `start()` is invoked, any running timer is canceled and a new timer starts.
    The timer is designed to be restarted many times over.

    Attributes
    ----------
    interval : float
        The delay (in seconds) after which the callback is invoked.
    callback : Callable
        The function to call when the timer expires.
    """

    def __init__(self, interval: float, callback: Callable, *args, **kwargs):
        self.interval = interval
        self.callback = callback
        self.args = args
        self.kwargs = kwargs

        self._timer: threading.Timer = None
        self._lock: threading.Lock = threading.RLock()

    def _run(self):
        """
        Internal method that runs in the timer thread.

        It clears the reference to the current timer (under the lock) so that the timer
        can be restarted, and then it calls the provided callback function.
        """
        with self._lock:
            self._timer = None

        self.callback(*self.args, **self.kwargs)

    def start(self):
        """
        Start or restart the timer. If there is a currently running timer,
        it is cancelled before a new one starts.
        """
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()

            self._timer = threading.Timer(self.interval, self._run)
            self._timer.daemon = True
            self._timer.start()

    def cancel(self):
        """
        Cancel the timer if it is currently running.
        """
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    restart = start


def build_sql_filters(data: dict, row_id: str = None) -> tuple[str, list]:
    # filters are chained and currently only support equality
    # if `row_id` is set, no other filters should be applied but we're
    # not going to stop you from doing it
    filters = data.get("filters", {})
    if row_id is not None:
        filters["id"] = row_id

    if filters:
        return (
            " WHERE " + " AND ".join(f"{k} = ?" for k in filters),
            list(filters.values()),
        )

    return "", []


def build_select_query(
    schema: str, data: dict = {}, row_id: Hashable = None
) -> tuple[str, list]:
    _columns = (
        [f"{schema}.{col}" for col in data["columns"]]
        if "columns" in data
        else [f"{schema}.*"]
    )
    _query = f"SELECT {', '.join(_columns)} FROM {schema}"

    f_query, _params = build_sql_filters(data, row_id)

    return _query + f_query, _params
