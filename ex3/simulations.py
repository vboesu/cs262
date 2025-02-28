import threading
import queue
import random
import time
from datetime import datetime

# Global parameters
NUM_MACHINES = 3         # Number of virtual machines
SIMULATION_TIME = 60     # seconds (set as needed)

# Create a dictionary of message queues, one per machine
message_queues = {i: queue.Queue() for i in range(NUM_MACHINES)}

# Event to signal the threads to stop
stop_event = threading.Event()

class Machine(threading.Thread):
    def __init__(self, machine_id, total_machines, queues, stop_event):
        super().__init__()
        self.machine_id = machine_id
        self.total_machines = total_machines
        self.queues = queues
        self.stop_event = stop_event

        # Determine clock rate: ticks per second in the range [1, 6]
        self.ticks_per_sec = random.randint(1, 6)
        self.tick_duration = 1.0 / self.ticks_per_sec

        # Initialize Lamport logical clock
        self.logical_clock = 0

        # Open log file for this machine
        self.log_filename = f"machine_{self.machine_id}.log"
        self.log_file = open(self.log_filename, "w")

    def log_event(self, event_type, details=""):
        # Get global system time as a string
        system_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Get current message queue length (for RECEIVE events)
        current_queue_length = self.queues[self.machine_id].qsize()
        log_line = f"{event_type} | System time: {system_time} | Logical clock: {self.logical_clock} | {details} | Queue length: {current_queue_length}\n"
        self.log_file.write(log_line)
        self.log_file.flush()

    def send_message(self, target_id):
        # For a send event, first increment clock then send the message
        self.logical_clock += 1
        msg = {
            "sender": self.machine_id,
            "timestamp": self.logical_clock
        }
        self.queues[target_id].put(msg)
        self.log_event("SEND", f"Sent to Machine {target_id}")

    def process_message(self, msg):
        # When receiving a message, update clock: max(local, received) + 1
        received_ts = msg["timestamp"]
        self.logical_clock = max(self.logical_clock, received_ts) + 1
        self.log_event("RECEIVE", f"Received from Machine {msg['sender']}")

    def internal_event(self):
        # Internal event: simply increment clock and log it.
        self.logical_clock += 1
        self.log_event("INTERNAL", "Internal event occurred")

    def run(self):
        while not self.stop_event.is_set():
            # On each clock tick
            if not self.queues[self.machine_id].empty():
                try:
                    msg = self.queues[self.machine_id].get_nowait()
                    self.process_message(msg)
                except queue.Empty:
                    pass
            else:
                # No incoming message, so generate a random event (1 to 10)
                event_choice = random.randint(1, 10)
                if event_choice == 1:
                    # Send to one randomly chosen other machine
                    targets = [i for i in range(self.total_machines) if i != self.machine_id]
                    target = random.choice(targets)
                    self.send_message(target)
                elif event_choice == 2:
                    # Send to a specific "other" machine (choose (id+1) mod total)
                    target = (self.machine_id + 1) % self.total_machines
                    self.send_message(target)
                elif event_choice == 3:
                    # Send to both of the other machines
                    targets = [i for i in range(self.total_machines) if i != self.machine_id]
                    for target in targets:
                        self.send_message(target)
                else:
                    # Internal event
                    self.internal_event()

            # Sleep for one tick duration
            time.sleep(self.tick_duration)
        # Close the log file when stopping
        self.log_file.close()

def main():
    # Create and start machines
    machines = []
    for i in range(NUM_MACHINES):
        m = Machine(i, NUM_MACHINES, message_queues, stop_event)
        machines.append(m)
        m.start()
        print(f"Machine {i} started with {m.ticks_per_sec} ticks/sec (tick duration: {m.tick_duration:.3f}s).")
    
    print(f"Running simulation for {SIMULATION_TIME} seconds...")
    time.sleep(SIMULATION_TIME)

    # Signal machines to stop and wait for them to finish
    stop_event.set()
    for m in machines:
        m.join()
    print("Simulation ended. Check the machine log files for details.")

if __name__ == "__main__":
    main()
