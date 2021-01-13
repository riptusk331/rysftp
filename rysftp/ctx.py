from functools import partial
import logging
from werkzeug.local import LocalStack, LocalProxy

from .errors import OutsideAppContextError

log = logging.getLogger(__name__)

_ry_ctx_err_msg = """\
Working outside of the connection context.\
This typically means that you attempted to use functionality that needed \
to interface with a connected application object in some way.\
"""


def _lookup_ry_object(name):
    top = _ry_ctx_stack.top
    if top is None:
        raise RuntimeError(_ry_ctx_err_msg)
    return getattr(top, name)


def _find_ry():
    top = _ry_ctx_stack.top
    if top is None:
        raise OutsideAppContextError(_ry_ctx_err_msg)
    return top.ry


class RyProxy:
    """A simple proxy class to forward requests to an object. The default
    implementation assumes a ``dict`` to be the proxied object.
    
    This provides a global space that can be used by many threads. It can be
    used as a packet buffer, where different threads can "trade" packets that
    aren't addressed to them. It can also be used to store threading Events for
    all our threads to listen to and play nicely together
    
    This is inspired by Werkzeug's 'LocalProxy' - I really like the concept of
    proxying a shared object, but the usage here called for something that's
    not always thread local.
    """

    def __init__(self, proxied):
        object.__setattr__(self, "__obj__", proxied)

    def __contains__(self, key):
        return key in self.__obj__

    def __getattr__(self, attr):
        try:
            return self.__obj__[attr]
        except KeyError:
            raise AttributeError(attr)

    def __setattr__(self, name, value):
        object.__setattr__(self.__obj__, name, value)

    def __delattr__(self, name):
        try:
            del self.__obj__[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, key):
        try:
            return self.__obj__[key]
        except KeyError:
            raise AttributeError(key)

    def __setitem__(self, key, item):
        self.__obj__[key] = item

    def __delitem__(self, key):
        try:
            del self.__obj__[key]
        except KeyError:
            raise AttributeError(key)

    def __iter__(self):
        return iter(self.__obj__.items())


_event_stack = RyProxy({})
_request_buffer = RyProxy({})
_ry_ctx_stack = LocalStack()
current_ry = LocalProxy(_find_ry)
g = RyProxy({})
lo = LocalProxy(partial(_lookup_ry_object, "lo"))


class RyContext:
    def __init__(self, ry):
        self.ry = ry
        self.lo = {}
        self._refcnt = 0

    def push(self):
        self._refcnt += 1
        _ry_ctx_stack.push(self)

    def pop(self):
        self._refcnt -= 1
        _ry_ctx_stack.pop()

    def __enter__(self):
        self.push()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        # self.pop(exc_value)
        # fix this at some point
        self.pop()
