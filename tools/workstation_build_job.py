"""Run an entire workstation job beneath the persistent compiler runner lock."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools')]
from workstation.project import Project
from workstation.toolchain import apply_codec_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', type=Path, required=True)
    args = parser.parse_args()
    directory = args.job.resolve(strict=True)
    inputs = json.loads((directory / 'worker-inputs.json').read_text())
    project = Project(inputs['root'], inputs['cache'], inputs['game'], inputs['sqlite'],
                      inputs.get('acts'), build_root=inputs.get('build_root'),
                      publication_root=inputs.get('publication_root'), recover_jobs=False,
                      codec_environment=inputs.get('codec_environment'))
    apply_codec_environment(project.codec_environment)
    job = project.job(directory.name)
    if directory != (project.jobs_dir / job['id']).resolve():
        raise ValueError('Worker job path differs from its configured cache')
    project._build(job)
    return 0 if project.job(job['id'])['status'] == 'succeeded' else 1


if __name__ == '__main__':
    raise SystemExit(main())
