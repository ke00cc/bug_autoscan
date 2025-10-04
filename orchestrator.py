# orchestrator.py
# Requires: Python 3.8+, tools installed and in PATH (subfinder, nuclei, semgrep)
# Usage: python orchestrator.py --domain example.com --out results/
import subprocess, json, os, argparse, datetime, uuid

def run_cmd(cmd, capture=True):
    print("[*] Running:", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=capture, text=True)
    if proc.returncode != 0:
        print("[!] Non‑zero exit:", proc.returncode)
    return proc.stdout

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def discovery(domain, outdir):
    out = os.path.join(outdir, "subfinder.json")
    cmd = ["subfinder", "-d", domain, "-silent", "-o", out]  # simple usage
    run_cmd(cmd)
    # subfinder writes plain lines — convert to list
    with open(out, "r") as f:
        hosts = [l.strip() for l in f if l.strip()]
    return hosts

def run_nuclei(targets, outdir):
    out = os.path.join(outdir, "nuclei.json")
    cmd = ["nuclei", "-l", "/dev/stdin", "-json", "-o", out]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
    p.stdin.write("\n".join(targets))
    p.stdin.close()
    p.wait()
    # parse JSON lines
    findings = []
    if os.path.exists(out):
        with open(out, "r") as f:
            for line in f:
                try:
                    findings.append(json.loads(line))
                except:
                    continue
    return findings

def run_semgrep(path, outdir):
    out = os.path.join(outdir, "semgrep.json")
    cmd = ["semgrep", "--config", "p/ci", "--json", "-o", out, path]  # example rule pack
    run_cmd(cmd)
    data = {}
    if os.path.exists(out):
        with open(out, "r") as f:
            data = json.load(f)
    return data

def aggregate_results(nuclei_findings, semgrep_data, outdir):
    summary = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
        "nuclei_count": len(nuclei_findings),
        "semgrep_count": len(semgrep_data.get("results", [])),
        "nuclei": nuclei_findings,
        "semgrep": semgrep_data,
    }
    with open(os.path.join(outdir, "aggregate.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print("[*] Aggregate written:", os.path.join(outdir, "aggregate.json"))
    return summary

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--out", default="results")
    parser.add_argument("--codepath", default=None, help="optional path for semgrep")
    args = parser.parse_args()

    ensure_dir(args.out)
    hosts = discovery(args.domain, args.out)
    print("[*] Discovered hosts:", hosts)
    nuclei_findings = run_nuclei(hosts, args.out)
    semgrep_data = {}
    if args.codepath:
        semgrep_data = run_semgrep(args.codepath, args.out)
    aggregate_results(nuclei_findings, semgrep_data, args.out)

if __name__ == "__main__":
    main()
