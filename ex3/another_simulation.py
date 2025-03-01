import threading
import queue
import random
import time
from datetime import datetime

# Global parameters for this simulation variant
NUM_MACHINES = 3           # Three virtual machines
SIMULATION_TIME = 60       # Run for 60 seconds

# Create a dictionary of message queues (one per machine)
message_queues = {i: queue.Queue() for i in range(NUM_MACHINES)}

# Event to signal threads to stop
stop_event = threading.Event()

class Machine(threading.Thread):
    def __init__(self, machine_id, total_machines, queues, stop_event):
        super().__init__()
        self.machine_id = machine_id
        self.total_machines = total_machines
        self.queues = queues
        self.stop_event = stop_event

        # Smaller variation in clock ticks:
        # Instead of 1-6, now choose either 3 or 4 ticks per second.
        self.ticks_per_sec = random.choice([3, 4])
        self.tick_duration = 1.0 / self.ticks_per_sec

        # Initialize Lamport logical clock
        self.logical_clock = 0

        # Open a log file for this machine
        self.log_filename = f"another_machine_{self.machine_id}.log"
        self.log_file = open(self.log_filename, "w")

    def log_event(self, event_type, details=""):
        system_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        current_queue_length = self.queues[self.machine_id].qsize()
        log_line = (f"{event_type} | System time: {system_time} | Logical clock: {self.logical_clock} | "
                    f"{details} | Queue length: {current_queue_length}\n")
        self.log_file.write(log_line)
        self.log_file.flush()

    def send_message(self, target_id):
        # For send, increment clock then send message
        self.logical_clock += 1
        msg = {
            "sender": self.machine_id,
            "timestamp": self.logical_clock
        }
        self.queues[target_id].put(msg)
        self.log_event("SEND", f"Sent to Machine {target_id}")

    def process_message(self, msg):
        received_ts = msg["timestamp"]
        self.logical_clock = max(self.logical_clock, received_ts) + 1
        self.log_event("RECEIVE", f"Received from Machine {msg['sender']}")

    def internal_event(self):
        self.logical_clock += 1
        self.log_event("INTERNAL", "Internal event occurred")

    def run(self):
        while not self.stop_event.is_set():
            # First, process any incoming messages
            if not self.queues[self.machine_id].empty():
                try:
                    msg = self.queues[self.machine_id].get_nowait()
                    self.process_message(msg)
                except queue.Empty:
                    pass
            else:
                # In this variant, we use a probability distribution where sending is more likely.
                # Probabilities:
                # 30% chance: send to one random other machine
                # 30% chance: send to the next machine ((id+1)%total)
                # 20% chance: send to both other machines
                # 20% chance: internal event
                r = random.random()  # r in [0,1)
                if r < 0.3:
                    # Send to one random machine (not self)
                    targets = [i for i in range(self.total_machines) if i != self.machine_id]
                    target = random.choice(targets)
                    self.send_message(target)
                elif r < 0.6:
                    # Send to the next machine in order
                    target = (self.machine_id + 1) % self.total_machines
                    self.send_message(target)
                elif r < 0.8:
                    # Send to both of the other machines
                    targets = [i for i in range(self.total_machines) if i != self.machine_id]
                    for target in targets:
                        self.send_message(target)
                else:
                    # Internal event with a smaller probability (20% chance)
                    self.internal_event()

            # Sleep for one tick duration
            time.sleep(self.tick_duration)
        # Clean up log file upon termination
        self.log_file.close()

def main():
    machines = []
    for i in range(NUM_MACHINES):
        m = Machine(i, NUM_MACHINES, message_queues, stop_event)
        machines.append(m)
        m.start()
        print(f"Machine {i} started with {m.ticks_per_sec} ticks/sec (tick duration: {m.tick_duration:.3f}s).")
    
    print(f"Running alternative simulation for {SIMULATION_TIME} seconds...")
    time.sleep(SIMULATION_TIME)
    
    stop_event.set()
    for m in machines:
        m.join()
    print("Alternative simulation ended. Check the log files (another_machine_*.log) for details.")

if __name__ == "__main__":
    main()
