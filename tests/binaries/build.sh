#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/src"
BIN_DIR="${SCRIPT_DIR}/bin"

mkdir -p "${BIN_DIR}"

# Check for gcc (required)
if ! command -v gcc &>/dev/null; then
    echo "ERROR: gcc is required but not found in PATH"
    exit 1
fi
echo "Found gcc: $(gcc --version | head -1)"

# Check for clang (optional)
HAVE_CLANG=false
if command -v clang &>/dev/null; then
    HAVE_CLANG=true
    echo "Found clang: $(clang --version | head -1)"
else
    echo "clang not found, skipping clang variants"
fi

# Common warning suppression flags
WARN_FLAGS="-Wno-deprecated-declarations -Wno-format-security -Wno-implicit-function-declaration"

# Compilation profiles
#   noprotect: no mitigations, debug info
#   protect:   full mitigations, FORTIFY_SOURCE (needs -O2)
#   O2_stripped: optimised, no mitigations, stripped
PROFILES=(
    "noprotect|-O0 -g -fno-stack-protector -no-pie -z execstack -z norelro"
    "protect|-O2 -g -fstack-protector-all -pie -D_FORTIFY_SOURCE=2 -z relro -z now"
    "O2_stripped|-O2 -fno-stack-protector -no-pie -s"
)

# Source files (basename without extension)
SOURCES=(vuln_stack_overflow vuln_format_string safe_program)

compile() {
    local compiler="$1"
    local compiler_label="$2"
    local src="$3"
    local name="$4"
    local profile_name="$5"
    local flags="$6"

    local out="${BIN_DIR}/${name}_${compiler_label}_${profile_name}"
    echo "  [${compiler_label}] ${name} (${profile_name}) -> $(basename "${out}")"
    # shellcheck disable=SC2086
    ${compiler} ${WARN_FLAGS} ${flags} -o "${out}" "${src}"
}

for source in "${SOURCES[@]}"; do
    src_file="${SRC_DIR}/${source}.c"
    if [[ ! -f "${src_file}" ]]; then
        echo "WARNING: source file not found: ${src_file}, skipping"
        continue
    fi

    echo "Compiling ${source}.c ..."

    for profile in "${PROFILES[@]}"; do
        IFS='|' read -r profile_name flags <<< "${profile}"

        # gcc (required)
        compile gcc gcc "${src_file}" "${source}" "${profile_name}" "${flags}"

        # clang (optional)
        if ${HAVE_CLANG}; then
            compile clang clang "${src_file}" "${source}" "${profile_name}" "${flags}"
        fi
    done
done

total=$(find "${BIN_DIR}" -type f -executable | wc -l)
echo ""
echo "Build complete: ${total} binaries in ${BIN_DIR}/"
exit 0
