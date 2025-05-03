import psycopg2
import psycopg2.extras
from pypgoutput import decode_message

# Connection string to your PostgreSQL database
# conn_str = "dbname=postgres user=postgres host=localhost port=12345"
conn_str = "postgres://postgres:password@127.0.0.1:5433/postgres"

# Use a replication connection
conn = psycopg2.connect(
    conn_str, connection_factory=psycopg2.extras.LogicalReplicationConnection
)
cur = conn.cursor()

# Attempt to create a replication slot if it doesn't already exist.
# You might wrap this in a try/except in production.
slot_name = "logical_slot"
try:
    cur.create_replication_slot(slot_name, output_plugin="pgoutput")
except psycopg2.ProgrammingError as e:
    # Slot may already exist—handle accordingly
    print("Replication slot may already exist:", e)
    conn.rollback()


# Callback function to process each WAL message
def replication_callback(msg):
    # Each message contains a payload with details of the transaction
    print("Raw payload:", msg.payload.hex())
    message = decode_message(msg.payload)
    print("message", message)

    # ***** Synchronous Example: *****
    # Here you might process the payload and apply it to a target replica.
    # Wait until you receive confirmation from the target system.
    # For example:
    # success = apply_to_replica(payload)
    # if success:
    #     msg.cursor.send_feedback(flush_lsn=msg.data_start)

    # ***** Asynchronous Example: *****
    # Instead, you might push the payload into a message queue for later processing:
    # message_queue.put(payload)
    #
    # After buffering the change, send feedback to PostgreSQL to advance the replication slot.
    msg.cursor.send_feedback(flush_lsn=msg.data_start)


# Start streaming replication messages (logical decoding stream)
try:
    cur.start_replication(
        slot_name=slot_name,
        options={"proto_version": "1", "publication_names": "all_writes"},
        decode=False,
    )
    cur.consume_stream(replication_callback)
except KeyboardInterrupt:
    print("Stopping replication stream.")

# Clean up the connection in a real-world application
