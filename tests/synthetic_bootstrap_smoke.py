import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command, label):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AssertionError(f"{label} failed ({result.returncode}): {(result.stdout + result.stderr)[-2000:]}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--container-test", type=Path, default=ROOT / "tests" / "cli_strict_container.py")
    args = parser.parse_args()
    cli = args.cli.resolve(strict=True)
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    simple = out / "synthetic-vs.asm"
    simple.write_text("vs_5_0\ndcl_output_siv o0.xyzw, position\n"
                      "mov o0.xyzw, l(0.0, 0.0, 0.0, 1.0)\nret\n", encoding="ascii")
    run([str(cli), "-a", str(simple)], "synthetic shader assembly")
    shader = simple.with_suffix(".shdr")
    run([str(cli), "-d", "-V", str(shader)], "synthetic -d -V validation")
    if not simple.with_suffix(".asm").is_file():
        raise AssertionError("disassembler did not write synthetic assembly")

    compute = out / "synthetic-cs.asm"
    compute.write_text("cs_5_1\ndcl_globalFlags refactoringAllowed | allResourcesBound\n"
                       "dcl_resource_raw T0[0:0], space=0\n"
                       "dcl_uav_raw U0[0:0], space=0\n"
                       "dcl_uav_typed_texture2d (uint,uint,uint,uint) U1[0:0], space=0\n"
                       "dcl_thread_group 1, 1, 1\n"
                       "store_uav_typed U1[0].x, l(0), l(0)\nret\n", encoding="ascii")
    run([str(cli), "-a", str(compute)], "synthetic compute shader assembly")
    compute_shader = compute.with_suffix(".shdr")
    run([str(cli), "-d", "-V", str(compute_shader)], "synthetic compute disassembly and exact-chunk validation")
    if not compute.with_suffix(".asm").is_file():
        raise AssertionError("disassembler did not write synthetic compute assembly")

    negated_mad = out / "synthetic-negated-mad.asm"
    negated_mad.write_text("cs_5_0\ndcl_temps 5\n"
                           "mad r2.xyz, -r4.xyzx, r0.yyyy, r1.xyzx\nret\n", encoding="ascii")
    run([str(cli), "-a", str(negated_mad)], "synthetic negated MAD assembly")
    run([str(cli), "-d", "-V", str(negated_mad.with_suffix(".shdr"))],
        "synthetic negated MAD exact round-trip")

    opaque_operand_ext = out / "synthetic-operand-extension.asm"
    opaque_operand_ext.write_text(
        "cs_5_0\ndcl_temps 5\n"
        "mad r2.xyz, r4.xyzx { operand_ext 0x00000001 }, r0.yyyy, r1.xyzx\nret\n",
        encoding="ascii")
    run([str(cli), "-a", str(opaque_operand_ext)], "synthetic explicit operand extension assembly")
    run([str(cli), "-d", "-V", str(opaque_operand_ext.with_suffix(".shdr"))],
        "synthetic no-op operand extension exact round-trip")

    invalid_extensions = {
        "malformed": "r4.xyzx { operand_ext 0x0000000g }",
        "unsupported-kind": "r4.xyzx { operand_ext 0x00000002 }",
        "continuation": "r4.xyzx { operand_ext 0x80000001 }",
        "modifier-conflict": "-r4.xyzx { operand_ext 0x00000001 }",
        "duplicate": "r4.xyzx { operand_ext 0x00000001 } { operand_ext 0x00000001 }",
        "trailing": "r4.xyzx { operand_ext 0x00000001 } junk",
        "missing-operand": "{ operand_ext 0x00000001 }",
    }
    for case_name, operand_text in invalid_extensions.items():
        invalid = out / f"synthetic-operand-extension-{case_name}.asm"
        invalid.write_text("cs_5_0\ndcl_temps 5\n"
                           f"mad r2.xyz, {operand_text}, r0.yyyy, r1.xyzx\nret\n",
                           encoding="ascii")
        rejected = subprocess.run([str(cli), "-a", str(invalid)], capture_output=True,
                                  text=True, timeout=60)
        if rejected.returncode == 0 or invalid.with_suffix(".shdr").exists():
            raise AssertionError(f"assembler accepted invalid operand extension annotation: {case_name}")

    cb = out / "synthetic-cbuffer.asm"
    cb_text = ("vs_5_0\ndcl_constantbuffer CB0[0:0][5], immediateIndexed\n"
               "dcl_output_siv o0.xyzw, position\n"
               "mov o0.xyzw, cb0[0][r2.w + 0].xyzw\nret\n")
    cb.write_text(cb_text, encoding="ascii")
    run([str(cli), "-a", str(cb)], "synthetic cbuffer operand assembly")
    cb_output = cb.with_suffix(".shdr")
    if not cb_output.is_file():
        raise AssertionError("assembler did not write synthetic cbuffer shader")
    malformed = out / "synthetic-cbuffer-malformed.asm"
    malformed.write_text(cb_text.replace("cb0[0][r2.w + 0]", "cb0[0]garbage[r2.w + 0]"), encoding="ascii")
    rejected = subprocess.run([str(cli), "-a", str(malformed)], capture_output=True, text=True, timeout=60)
    if rejected.returncode == 0 or malformed.with_suffix(".shdr").exists():
        raise AssertionError("assembler accepted a nonadjacent constant-buffer bracket")

    container = run([sys.executable, str(args.container_test), "--cli", str(cli), "--fixture", str(shader),
                     "--receipt-output", str(out / "strict-container.json")], "synthetic malformed-container suite")
    summary = json.loads(container.stdout)
    if summary.get("status") != "pass" or summary.get("passed") != 5:
        raise AssertionError("strict container suite did not pass all authored malformed cases")
    receipt = {"schema": "replay120-dxbc-synthetic-bootstrap-smoke-v1", "status": "pass",
               "operations": ["synthetic CLI assembly", "synthetic compute-stage assembly/disassembly",
                              "disassemble/-V exact all-chunk check",
                              "exact raw operand-extension round-trip and malformed annotation rejection",
                              "valid ranged cbuffer operand", "nonadjacent bracket rejection"],
               "container_tests": summary}
    (out / "synthetic-smoke-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "pass", "container_cases": summary["passed"],
                      "synthetic_shader_bytes": shader.stat().st_size,
                      "synthetic_compute_shader_bytes": compute_shader.stat().st_size}, indent=2))


if __name__ == "__main__":
    main()
