import concurrent.futures
import argparse
import threading
import queue
import random
import time
import socket
import json
from datetime import datetime
from pathlib import Path

# Global parameters
NUM_MACHINES = 3  # Number of virtual machines

# Constants, overwriteable by command line arguments
SIMULATION_TIME = 60  # Simulation duration in seconds
BASE_PORT = 50000  # Base port for machine sockets
HOST = "localhost"  # Host for socket communication
TICKS_MIN = 1  # Minimum number of ticks per second
TICKS_MAX = 6  # Maximum number of ticks per second
WEIGHT_INTERNAL = 7.0  # Weight of internal events

FOLDER = Path(__file__).resolve().parent
LOGS_FOLDER = FOLDER / "logs"


class Machine:
    def __init__(
        self,
        id: int,
        tick_speed: float = 1.0,
        weight_internal: float = 7.0,
        host: str = "localhost",
        base_port: int = 50000,
        runtime: float = 60.0,
    ):
        self.id = id
        self.tick_speed = tick_speed
        self.weight_internal = weight_internal
        self.runtime = runtime

        # Logical clock
        self.clock = 0

        # Server setup
        self.host = host
        self.base_port = base_port
        self.port = self.base_port + id

        # Logging
        self.log_filename = LOGS_FOLDER / f"machine_{self.id}.log"
        self.log_file = open(self.log_filename, "w")

        # Set up sockets
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)

        # Threading stuff for communication
        self.listener_thread = threading.Thread(target=self.listen)
        self.messages = queue.Queue()

        # Threading stuff for runtime
        self.stop_event = threading.Event()
        self.stop_timer = threading.Timer(self.runtime, self.mark_stop)

        time.sleep(2)  # wait for other processes to finish setup
        self.start()

    @classmethod
    def create(
        cls,
        id: int,
        ticks_min: int = 1,
        ticks_max: int = 6,
        weight_internal: float = 7.0,
        host: str = "localhost",
        base_port: int = 50000,
        runtime: float = 60.0,
    ):
        tick_speed = 1 / random.randint(ticks_min, ticks_max)

        # Instantiate machine
        cls(id, tick_speed, weight_internal, host, base_port, runtime)

    def log(self, event, details: str = ""):
        system_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        queue_length = self.messages.qsize()
        log_line = " | ".join(
            [
                f"M{self.id}",
                system_time,
                event,
                f"Clock: {self.clock}",
                f"Queue: {queue_length}",
                details,
            ]
        )
        self.log_file.write(f"{log_line}\n")
        self.log_file.flush()

    def generate_event(self) -> str:
        if self.messages.qsize() > 0:
            return "REC"

        events = [
            "SE1",  # send to (self.id + 1) mod 3
            "SE2",  # send to (self.id + 2) mod 3
            "SEA",  # send to all other machines
            "INT",  # internal
        ]

        return random.choices(events, [1.0] * 3 + [self.weight_internal])[0]

    def send_message(self, target_ids: list[int]):
        message = {"sender": self.id, "ts": self.clock}

        for target_id in target_ids:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.base_port + target_id))
                s.sendall(json.dumps(message).encode())

    def run(self):
        while not self.stop_event.is_set():
            event = self.generate_event()

            if event == "REC":
                message = self.messages.get()

                self.clock = max(self.clock, message["ts"])
            elif event == "SE1":
                self.send_message([(self.id + 1) % NUM_MACHINES])
            elif event == "SE2":
                self.send_message([(self.id + 2) % NUM_MACHINES])
            elif event == "SEA":
                self.send_message(
                    [
                        (self.id + 1) % NUM_MACHINES,
                        (self.id + 2) % NUM_MACHINES,
                    ]
                )

            self.clock += 1
            self.log(event)

            # Simulate tick speed
            time.sleep(self.tick_speed)

        self.stop()

    def start(self):
        self.log("START", f"tick speed: {self.tick_speed}, runtime: {self.runtime}")
        self.listener_thread.start()
        self.stop_timer.start()

        self.run()

    def stop(self):
        self.log("STOP")
        self.listener_thread.join()
        self.server_socket.close()
        self.log_file.close()

    def listen(self):
        while not self.stop_event.is_set():
            try:
                conn, addr = self.server_socket.accept()
                with conn:
                    data = conn.recv(1024)
                    if data:
                        self.messages.put(json.loads(data.decode()))

            except socket.timeout:
                continue
            except Exception:
                continue

    def mark_stop(self):
        self.stop_event.set()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Logical Clock Model Simulation")
    parser.add_argument(
        "--host",
        type=str,
        default=HOST,
        help=f"Host/IP to bind or connect to (default: {HOST})",
    )
    parser.add_argument(
        "-b",
        "--base-port",
        type=int,
        default=BASE_PORT,
        help=f"Base port for simulated machines (default: {BASE_PORT})",
    )
    parser.add_argument(
        "-r",
        "--runtime",
        type=int,
        default=SIMULATION_TIME,
        help=f"Runtime of simulation in seconds (default: {SIMULATION_TIME})",
    )
    parser.add_argument(
        "-i",
        "--internal",
        type=float,
        default=WEIGHT_INTERNAL,
        help=f"Relative weight of internal events in event generation (default: {WEIGHT_INTERNAL})",
    )
    parser.add_argument(
        "--ticks-min",
        type=int,
        default=TICKS_MIN,
        help=f"Minimum number of ticks (default: {TICKS_MIN})",
    )
    parser.add_argument(
        "--ticks-max",
        type=int,
        default=TICKS_MAX,
        help=f"Maximum number of ticks (default: {TICKS_MAX})",
    )

    args = parser.parse_args()
    LOGS_FOLDER.mkdir(exist_ok=True)

    futures = []
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for i in range(NUM_MACHINES):
            futures.append(
                executor.submit(
                    Machine.create,
                    i,
                    args.ticks_min,
                    args.ticks_max,
                    args.internal,
                    args.host,
                    args.base_port,
                    args.runtime,
                )
            )

    # Wait for all processes to finish
    concurrent.futures.wait(futures)
    for future in futures:
        future.result()
