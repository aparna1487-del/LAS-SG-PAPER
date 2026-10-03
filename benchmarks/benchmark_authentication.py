import json, statistics, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from las_sg import NANGateway, SmartMeter


def main(rounds=100):
    gw = NANGateway(master_secret=123456789)
    sm = SmartMeter(gw.register("sm-001"))
    times, sizes = [], []
    for i in range(rounds):
        t0 = time.perf_counter()
        m1 = sm.message1(now=1000 + i * 2)
        m2, k1 = gw.authenticate(m1, now=1001 + i * 2)
        k2 = sm.finish(m1, m2, now=1001 + i * 2)
        assert k1 == k2
        times.append((time.perf_counter() - t0) * 1000)
        sizes.append(sum(len(str(v).encode()) for k, v in m1.items() if not k.startswith("_")) + sum(len(str(v).encode()) for v in m2.values()))
    result = {"rounds": rounds, "median_ms": statistics.median(times), "mean_ms": statistics.mean(times), "p95_ms": sorted(times)[int(.95 * len(times)) - 1], "mean_message_bytes_approx": statistics.mean(sizes)}
    print(json.dumps(result, indent=2))

if __name__ == "__main__": main()
