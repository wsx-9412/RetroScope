#!/bin/bash
# Sweep target versions for CVE-2022-3627: start at 4.0.5, go older.
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSIONS=(4.0.4 4.0.4beta 4.0.3 4.0.2 4.0.1 4.0.0 3.9.6 3.9.5 3.9.4 3.9.3)

for ver in "${VERSIONS[@]}"; do
    echo "========================================================"
    echo "[$(date '+%F %T')] START target=tiff-$ver"
    echo "========================================================"
    # Update TARGET_VERSION_PATH for libtiff in run_analysis.sh
    sed -i "s|TARGET_VERSION_PATH=\"\$BASE_DIR/tiff-versions/tiff-[^\"]*\"|TARGET_VERSION_PATH=\"\$BASE_DIR/tiff-versions/tiff-$ver\"|" run_analysis.sh
    grep -n 'tiff-versions/tiff-' run_analysis.sh | head -2
    ./run_analysis.sh config_libtiff.py
    rc=$?
    echo "[$(date '+%F %T')] DONE target=tiff-$ver rc=$rc"
    echo ""
done
echo "[$(date '+%F %T')] ALL VERSIONS COMPLETED"
