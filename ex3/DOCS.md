# Design Exercise 3: Logical Clocks

## Architecture
Each machine is simulated by an instantiation of the `Machine` class with a unique `id`, and is created in its own process. It then connects to the other machines by assuming a common host and the port `BASE_PORT + target_id` for a machine with the ID `target_id`.

## Testing
We created unit tests for the `Machine` class. To run the tests, run
```
python -m pytest test_simulate.py
```

## Usage
To run a simulation with the default settings, run
```
python simulate.py
```

Additional options can be viewed by running
```
python simulate.py --help
```
## Happy simulating!