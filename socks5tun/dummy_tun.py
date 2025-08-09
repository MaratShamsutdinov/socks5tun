"""
Dummy TUN interface for simulating a TUN device.
"""

import threading
import traceback
import logging
from collections import deque


class DummyTun:
    """
    A dummy TUN interface that mimics a TUN device for testing or environments
    where a real TUN device is not available.
    Data written to this dummy interface
    is stored, and data can be injected for reading.
    """

    def __init__(self):
        # Queues for incoming (to be read) and outgoing (written) data
        self._incoming_data = deque()
        self._outgoing_data = deque()
        self._lock = threading.Lock()
        # Conditions to wait for data availability
        self._incoming_cond = threading.Condition(self._lock)
        self._outgoing_cond = threading.Condition(self._lock)
        self.active = False

    def open(self):
        """
        Open/initialize the dummy TUN interface.
        (For a real TUN, this would create the TUN device.
        Here we just mark it active.)
        """
        with self._lock:
            self.active = True

    def read(self, size: int = 1500) -> bytes:
        """
        Read data from the dummy TUN interface
        (blocking until data is available or interface is closed).
        Returns bytes of data, or b'' if the interface is closed.
        """
        with self._incoming_cond:
            # Wait until data is available or the interface becomes inactive
            while not self._incoming_data and self.active:
                self._incoming_cond.wait()
            if not self.active and not self._incoming_data:
                # Interface closed and no data remaining
                return b""
            data = self._incoming_data.popleft()
        # Return up to 'size' bytes from the data (simulate reading a packet)
        if size and len(data) > size:
            remaining = data[size:]
            # Put the remaining back to be read next time
            with self._incoming_cond:
                self._incoming_data.appendleft(remaining)
            return data[:size]
        else:
            return data

    def write(self, data: bytes) -> int:
        """
        Write data to the dummy TUN interface.
        (For a real TUN, this would send the packet into the OS network stack.)
        Here we store it in an outgoing queue for inspection.
        Returns the number of bytes written.
        """
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            print("🔄 DummyTun.write() called by:")
            traceback.print_stack(limit=5)
        traceback.print_stack(limit=5)
        with self._outgoing_cond:
            self._outgoing_data.append(data)
            # Notify any waiters for outgoing data (if used in tests)
            self._outgoing_cond.notify_all()
        return len(data)

    def inject(self, data: bytes):
        """
        Inject data into the dummy TUN interface as
        if it was received from the network.
        This data will be available to read() by the server.
        """
        with self._incoming_cond:
            self._incoming_data.append(data)
            # Notify any thread waiting for incoming data
            self._incoming_cond.notify_all()

    def close(self):
        """
        Close the dummy TUN interface.
        """
        with self._incoming_cond:
            self.active = False
            # Wake up any waiting readers so they can stop
            self._incoming_cond.notify_all()
