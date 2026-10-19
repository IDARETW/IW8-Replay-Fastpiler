"""Run the portable native adapter regressions under normal test discovery."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from tools.test_workstation_native_asset_edits import NativeAssetEditTests
