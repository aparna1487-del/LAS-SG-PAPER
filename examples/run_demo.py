#!/usr/bin/env python3
"""Run one complete LAS-SG smart-meter/NAN authentication session."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from las_sg import NANGateway, SmartMeter


def main():
    gateway = NANGateway(master_secret=123456789)
    registration = gateway.register("sm-demo-001")
    meter = SmartMeter(registration)

    message1 = meter.message1(now=1000.0)
    message2, gateway_key = gateway.authenticate(message1, now=1001.0)
    meter_key = meter.finish(message1, message2, now=1001.0)

    print("LAS-SG authentication demo")
    print(f"Smart meter: {registration.smid}")
    print(f"Message 1: {list(k for k in message1 if not k.startswith('_'))}")
    print(f"Message 2: {list(message2)}")
    print(f"Mutual authentication successful: {gateway_key == meter_key}")
    print(f"Session key: {meter_key.hex()}")


if __name__ == "__main__":
    main()
