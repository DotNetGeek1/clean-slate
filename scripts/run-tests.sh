#!/usr/bin/env bash
# Run Clean-Slate QEMU xtask acceptance tests and report failures.
#
# By default runs test-m1, test-m2, test-m3, test-m4, test-m5, test-m6, test-m7, test-m8
# (milestone gates and aggregates). Use --exhaustive for every registered xtask acceptance command.
# OVMF is discovered by xtask on Linux when
# OVMF_CODE/OVMF_VARS are unset; override with env vars or --ovmf-code/--ovmf-vars.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_PATH="${REPORT_PATH:-$REPO_ROOT/target/xtask-test-report.txt}"

EXHAUSTIVE=0
LIST=0
OVMF_CODE_OVERRIDE=""
OVMF_VARS_OVERRIDE=""
REQUESTED=()

# Ordered registry (matches scripts/run-tests.ps1).
TEST_NAMES=(
  test-m1
  test-m2
  test-m3
  test-m3-entry
  test-m3-address-space
  test-m3-syscall
  test-m3-lifecycle
  test-m3-ipc
  test-m3-resources
  test-m4-crash-service
  test-m4-service-lifecycle
  test-m4-restart-policy
  test-m4-supervisor
  test-m4
  test-m4-recovery
  test-m5
  test-m5-block
  test-m5-storage
  test-m5-crash-matrix
  test-m5-persistence
  test-m5-crash-recovery
  test-m5-disk-harness
  test-m6
  test-m7
  test-m8
  test-m6-fixture-smoke
  test-m6-object
  test-m7-net-service
  test-m7-network
  test-m6-process-control
  test-m6-delegation
  test-m6-revocation
  test-m6-audit
  test-m6-capabilities
  test-m7-net-device
  test-m7-tls
  test-m7-net-caps
  test-m7-dns
  test-m8-linux-hello
  test-m8-linux-image
  test-m8-linux-dispatch
  test-m9-syscall-fail-closed
  test-m9-block-wake
  test-m9-fd-core
  test-m9-low-va
  test-m9-linux-exec
  test-m9-linux-proc
  test-m9-rootfs
  verify-m8-fixture
  verify-m9-fixture
)

test_role() {
  case "$1" in
    test-m3-entry | test-m3-address-space | test-m3-syscall | test-m3-lifecycle | test-m3-ipc | test-m3-resources | test-m4-crash-service | test-m4-service-lifecycle | test-m4-restart-policy | test-m4-recovery | test-m4-supervisor | test-m5-block | test-m5-storage | test-m5-crash-matrix | test-m5-persistence | test-m5-crash-recovery | test-m5-disk-harness | test-m6-fixture-smoke | test-m6-object | test-m6-process-control | test-m6-delegation | test-m6-revocation | test-m6-audit | test-m6-capabilities | test-m7-net-service | test-m7-network | test-m7-net-device | test-m7-net-caps | test-m7-dns | test-m7-tls | test-m8-linux-hello | test-m8-linux-image | test-m8-linux-dispatch | test-m9-syscall-fail-closed | test-m9-block-wake | test-m9-fd-core | test-m9-low-va | test-m9-linux-exec | test-m9-linux-proc | test-m9-rootfs | verify-m8-fixture | verify-m9-fixture)
      echo Constituent
      ;;
    test-m3 | test-m4 | test-m5 | test-m6 | test-m7 | test-m8)
      echo Aggregate
      ;;
    *)
      echo Milestone
      ;;
  esac
}

test_description() {
  case "$1" in
    test-m1) echo "M1 memory acceptance" ;;
    test-m2) echo "M2 interrupt/timer/scheduler acceptance" ;;
    test-m3) echo "M3 milestone gate (aggregate of all M3 acceptance boots)" ;;
    test-m3-entry) echo "M3.1 userspace-entry acceptance" ;;
    test-m3-address-space) echo "M3.2 address-space isolation acceptance" ;;
    test-m3-syscall) echo "M3.3 native-syscall acceptance" ;;
    test-m3-lifecycle) echo "M3.4 process/thread lifecycle acceptance" ;;
    test-m3-ipc) echo "M3.5 capability-authorized IPC acceptance" ;;
    test-m3-resources) echo "M3.6 domain resource accounting/teardown acceptance" ;;
    test-m4-crash-service) echo "M4.7 supervised crash-service fixture acceptance" ;;
    test-m4-service-lifecycle) echo "M4.2 kernel service lifecycle control acceptance" ;;
    test-m4-restart-policy) echo "M4.6 supervisor restart-policy convergence (host + userspace image build)" ;;
    test-m4-supervisor) echo "M4.3 userspace supervisor runtime QEMU integration acceptance" ;;
    test-m4) echo "M4 milestone gate (recovery QEMU boot + M4.6 host policy tests)" ;;
    test-m4-recovery) echo "M4.8 authoritative recovery QEMU acceptance" ;;
    test-m5) echo "M5 milestone gate (block I/O, storage integration, reboot persistence, crash recovery)" ;;
    test-m5-block) echo "M5.2 VirtIO block transport QEMU acceptance" ;;
    test-m5-storage) echo "M5.7 integrated storage-path acceptance" ;;
    test-m5-crash-matrix) echo "M5.6 host crash-consistency matrix" ;;
    test-m5-persistence) echo "M5 reboot-persistence acceptance on the persistent QEMU disk" ;;
    test-m5-crash-recovery) echo "M5 abrupt-stop crash-recovery acceptance on the persistent QEMU disk" ;;
    test-m5-disk-harness) echo "M5 harness-only two-boot disk fixture validation (host sentinel)" ;;
    test-m6-fixture-smoke) echo "M6 scripted fixture harness smoke (constituent)" ;;
    test-m6-object) echo "M6.3 persistent object capability constituent acceptance" ;;
    test-m7-net-service) echo "M7.3 network service and driver-domain seam acceptance" ;;
    test-m7-network) echo "M7.8 converged production path acceptance (service + capability + DNS/TCP/TLS)" ;;
    test-m6-process-control) echo "M6.4 process-control capability constituent acceptance" ;;
    test-m6-delegation) echo "M6.5 capability delegation and attenuation constituent acceptance" ;;
    test-m6-revocation) echo "M6.6 capability revocation and teardown constituent acceptance" ;;
    test-m6-audit) echo "M6.7 capability audit events constituent acceptance" ;;
    test-m6-capabilities) echo "M6.8 capability convergence acceptance" ;;
    test-m7-net-device) echo "M7.2 VirtIO-net device-lane QEMU acceptance" ;;
    test-m7-tls) echo "M7.6 TLS client QEMU acceptance (pass + fail-closed)" ;;
    test-m7-net-caps) echo "M7.7 network capability broker and attribution acceptance" ;;
    test-m7-dns) echo "M7.5 DNS resolver QEMU acceptance" ;;
    test-m6) echo "M6 milestone gate (capability host tests, fixture smoke, constituents, convergence)" ;;
    test-m7) echo "M7 milestone gate (converged network-service path + DNS/TLS + capability broker)" ;;
    test-m8) echo "M8 milestone gate (fixture verify, elf/linux-abi/#92 host tests, Linux hello production path)" ;;
    test-m8-linux-hello) echo "M8.7 integrated Linux hello (self-test observer + production boot)" ;;
    test-m8-linux-image) echo "M8.2 Linux ELF loader QEMU constituent acceptance" ;;
    test-m8-linux-dispatch) echo "M8.3 Linux personality dispatch QEMU constituent acceptance" ;;
    test-m9-syscall-fail-closed) echo "M9 #143 unresolved syscall caller fail-closed QEMU acceptance" ;;
    test-m9-block-wake) echo "M9 #145 native block/wake scheduler substrate QEMU acceptance" ;;
    test-m9-fd-core) echo "M9 #147 Linux fd / open-description core QEMU acceptance" ;;
    test-m9-low-va) echo "M9 #142 low canonical user VA acceptance" ;;
    test-m9-linux-exec) echo "M9 #146 Linux exec substrate acceptance" ;;
    test-m9-linux-proc) echo "M9 #102 Linux fork/pipe/wait acceptance" ;;
    test-m9-rootfs) echo "M9 #104 embedded rootfs fixture acceptance" ;;
    verify-m8-fixture) echo "M8.6 fixture SHA-256 and ELF metadata verify (host)" ;;
    verify-m9-fixture) echo "M9 #104 BusyBox + rootfs fixture verify (host)" ;;
    *) echo "" ;;
  esac
}

test_aliases() {
  case "$1" in
    test-m1) echo "m1" ;;
    test-m2) echo "m2" ;;
    test-m3) echo "m3 m3.7" ;;
    test-m3-entry) echo "m3-entry entry m3.1" ;;
    test-m3-address-space) echo "m3-address-space address-space m3.2" ;;
    test-m3-syscall) echo "m3-syscall syscall m3.3" ;;
    test-m3-lifecycle) echo "m3-lifecycle lifecycle m3.4" ;;
    test-m3-ipc) echo "m3-ipc ipc m3.5" ;;
    test-m3-resources) echo "m3-resources resources m3.6" ;;
    test-m4-crash-service) echo "m4-crash-service crash-service m4.7" ;;
    test-m4-service-lifecycle) echo "m4-service-lifecycle service-lifecycle m4.2" ;;
    test-m4-restart-policy) echo "m4-restart-policy restart-policy m4.6" ;;
    test-m4-supervisor) echo "m4-supervisor supervisor m4.3" ;;
    test-m4) echo "m4 m4.8" ;;
    test-m4-recovery) echo "m4-recovery recovery m4.8-qemu" ;;
    test-m5) echo "m5" ;;
    test-m5-block) echo "m5-block block-attach" ;;
    test-m5-storage) echo "m5-storage m5.7" ;;
    test-m5-crash-matrix) echo "m5-crash-matrix crash-matrix m5.6" ;;
    test-m5-persistence) echo "m5-persistence reboot-persistence" ;;
    test-m5-crash-recovery) echo "m5-crash-recovery crash-recovery" ;;
    test-m5-disk-harness) echo "m5-disk-harness m5-harness" ;;
    test-m6-fixture-smoke) echo "m6-fixture-smoke" ;;
    test-m6-object) echo "m6-object m6.3" ;;
    test-m7-net-service) echo "m7-net-service m7.3" ;;
    test-m7-network) echo "m7-network m7.8" ;;
    test-m6-process-control) echo "m6-process-control m6.4" ;;
    test-m6-delegation) echo "m6-delegation m6.5" ;;
    test-m6-revocation) echo "m6-revocation m6.6" ;;
    test-m6-audit) echo "m6-audit m6.7" ;;
    test-m6-capabilities) echo "m6-capabilities m6.8" ;;
    test-m7-net-device) echo "m7-net-device m7.2" ;;
    test-m7-tls) echo "m7-tls m7.6" ;;
    test-m7-net-caps) echo "m7-net-caps m7.7" ;;
    test-m7-dns) echo "m7-dns m7.5" ;;
    test-m6) echo "m6 m6.9" ;;
    test-m7) echo "m7 m7.9" ;;
    test-m8) echo "m8 m8.9" ;;
    test-m8-linux-hello) echo "m8-linux-hello m8.7" ;;
    test-m8-linux-image) echo "m8-linux-image m8.2" ;;
    test-m8-linux-dispatch) echo "m8-linux-dispatch m8.3" ;;
    test-m9-syscall-fail-closed) echo "m9-syscall-fail-closed m9.143" ;;
    test-m9-block-wake) echo "m9-block-wake m9.145" ;;
    test-m9-fd-core) echo "m9-fd-core m9.147" ;;
    test-m9-low-va) echo "m9-low-va m9.142" ;;
    test-m9-linux-exec) echo "m9-linux-exec m9.146" ;;
    test-m9-linux-proc) echo "m9-linux-proc m9.102" ;;
    test-m9-rootfs) echo "m9-rootfs m9.104" ;;
    verify-m8-fixture) echo "verify-m8-fixture" ;;
    verify-m9-fixture) echo "verify-m9-fixture" ;;
    *) echo "" ;;
  esac
}

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \?//'
  echo ""
  echo "Options:"
  echo "  --exhaustive       Run every known test"
  echo "  --list             List tests and exit"
  echo "  --ovmf-code PATH   Set OVMF_CODE"
  echo "  --ovmf-vars PATH   Set OVMF_VARS"
  echo "  --report PATH      Report file (default: target/xtask-test-report.txt)"
  echo "  -h, --help         Show this help"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exhaustive)
      EXHAUSTIVE=1
      shift
      ;;
    --list)
      LIST=1
      shift
      ;;
    --ovmf-code)
      OVMF_CODE_OVERRIDE="$2"
      shift 2
      ;;
    --ovmf-vars)
      OVMF_VARS_OVERRIDE="$2"
      shift 2
      ;;
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        REQUESTED+=("$1")
        shift
      done
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      REQUESTED+=("$1")
      shift
      ;;
  esac
done

show_test_list() {
  echo "Available tests:"
  for name in "${TEST_NAMES[@]}"; do
    role="$(test_role "$name")"
    case "$role" in
      Aggregate) tag="[aggregate]  " ;;
      Constituent) tag="[constituent]" ;;
      *) tag="[milestone]  " ;;
    esac
    desc="$(test_description "$name")"
    aliases="$(test_aliases "$name")"
    printf "  %-24s %s %s\n" "$name" "$tag" "$desc"
    printf "  %-24s %s aliases: %s\n" "" "" "$aliases"
  done
  echo ""
  echo -n "Default suite:  "
  first=1
  for name in "${TEST_NAMES[@]}"; do
    if [[ "$(test_role "$name")" != Constituent ]]; then
      [[ $first -eq 0 ]] && echo -n ", "
      echo -n "$name"
      first=0
    fi
  done
  echo ""
  echo "--exhaustive:    ${TEST_NAMES[*]}"
  echo "Constituents are per-boundary debugging workflows behind aggregate milestone commands and standalone acceptance lanes."
}

resolve_test_name() {
  local requested="${1,,}"
  local name aliases alias
  for name in "${TEST_NAMES[@]}"; do
    if [[ "$requested" == "$name" ]]; then
      echo "$name"
      return 0
    fi
    read -r -a aliases <<< "$(test_aliases "$name")"
    for alias in "${aliases[@]}"; do
      if [[ "$requested" == "${alias,,}" ]]; then
        echo "$name"
        return 0
      fi
    done
  done
  echo "Unknown test '$1'." >&2
  echo -n "Known names: " >&2
  local known=()
  for name in "${TEST_NAMES[@]}"; do
    known+=("$name")
    read -r -a aliases <<< "$(test_aliases "$name")"
    known+=("${aliases[@]}")
  done
  echo "${known[*]}" >&2
  exit 1
}

format_duration() {
  local total_ms="$1"
  local mins=$((total_ms / 60000))
  local secs=$(((total_ms % 60000) / 1000))
  local frac=$(((total_ms % 1000) / 100))
  if [[ $mins -ge 1 ]]; then
    printf "%dm %d.%ds" "$mins" "$secs" "$frac"
  else
    printf "%d.%ds" "$secs" "$frac"
  fi
}

get_failure_details() {
  local file="$1"
  local patterns=(
    "error:"
    "ERROR"
    "failed with status"
    "timed out"
    "missing required marker"
    "OVMF firmware not found"
    "unknown command"
    "FAIL"
  )
  local hits=()
  local line pattern trimmed
  while IFS= read -r line || [[ -n "$line" ]]; do
    for pattern in "${patterns[@]}"; do
      if [[ "$line" == *"$pattern"* ]]; then
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        if [[ -n "$trimmed" ]]; then
          hits+=("$trimmed")
        fi
        break
      fi
    done
  done <"$file"
  if [[ ${#hits[@]} -gt 0 ]]; then
    local start=$(( ${#hits[@]} > 12 ? ${#hits[@]} - 12 : 0 ))
    for ((i = start; i < ${#hits[@]}; i++)); do
      echo "${hits[$i]}"
    done
    return
  fi
  tail -n 15 "$file" | sed '/^[[:space:]]*$/d' || true
  if [[ ! -s "$file" ]]; then
    echo "No captured output."
  fi
}

if [[ $LIST -eq 1 ]]; then
  show_test_list
  exit 0
fi

SELECTED=()
if [[ ${#REQUESTED[@]} -gt 0 ]]; then
  declare -A seen=()
  for item in "${REQUESTED[@]}"; do
    name="$(resolve_test_name "$item")"
    if [[ -z "${seen[$name]+x}" ]]; then
      SELECTED+=("$name")
      seen[$name]=1
    fi
  done
elif [[ $EXHAUSTIVE -eq 1 ]]; then
  SELECTED=("${TEST_NAMES[@]}")
else
  for name in "${TEST_NAMES[@]}"; do
    if [[ "$(test_role "$name")" != Constituent ]]; then
      SELECTED+=("$name")
    fi
  done
fi

if [[ -n "$OVMF_CODE_OVERRIDE" ]]; then
  export OVMF_CODE="$OVMF_CODE_OVERRIDE"
fi
if [[ -n "$OVMF_VARS_OVERRIDE" ]]; then
  export OVMF_VARS="$OVMF_VARS_OVERRIDE"
fi

cd "$REPO_ROOT"

echo ""
echo "Clean-Slate xtask suite"
echo "  repo     $REPO_ROOT"
if [[ -n "${OVMF_CODE:-}" ]]; then
  echo "  OVMF_CODE  $OVMF_CODE"
fi
if [[ -n "${OVMF_VARS:-}" ]]; then
  echo "  OVMF_VARS  $OVMF_VARS"
fi
echo "  tests    ${SELECTED[*]}"
echo ""

started_at="$(date '+%Y-%m-%d %H:%M:%S')"
started_epoch="$(date +%s)"

declare -a result_names=()
declare -a result_passed=()
declare -a result_exit=()
declare -a result_duration_ms=()
declare -a result_log_files=()

for name in "${SELECTED[@]}"; do
  echo "======== $name ========"
  log_file="$(mktemp)"
  result_log_files+=("$log_file")
  start_ms="$(date +%s%3N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1000))')"
  set +e
  cargo xtask "$name" 2>&1 | tee "$log_file"
  exit_code="${PIPESTATUS[0]}"
  set -e
  end_ms="$(date +%s%3N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1000))')"
  duration_ms=$((end_ms - start_ms))

  result_names+=("$name")
  result_exit+=("$exit_code")
  result_duration_ms+=("$duration_ms")

  if [[ $exit_code -eq 0 ]]; then
    result_passed+=(1)
    echo "PASS  $name  ($(format_duration "$duration_ms"))"
  else
    result_passed+=(0)
    echo "FAIL  $name  ($(format_duration "$duration_ms"), exit $exit_code)"
  fi
  echo ""
done

finished_epoch="$(date +%s)"
total_ms=$(((finished_epoch - started_epoch) * 1000))

passed_count=0
failed_count=0
for p in "${result_passed[@]}"; do
  if [[ $p -eq 1 ]]; then
    passed_count=$((passed_count + 1))
  else
    failed_count=$((failed_count + 1))
  fi
done

mkdir -p "$(dirname "$REPORT_PATH")"
{
  echo "Clean-Slate xtask test report"
  echo "Started:  $started_at"
  echo "Finished: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "Duration: $(format_duration "$total_ms")"
  [[ -n "${OVMF_CODE:-}" ]] && echo "OVMF_CODE: $OVMF_CODE"
  [[ -n "${OVMF_VARS:-}" ]] && echo "OVMF_VARS: $OVMF_VARS"
  echo ""
  for i in "${!result_names[@]}"; do
    if [[ ${result_passed[$i]} -eq 1 ]]; then
      status="PASS"
    else
      status="FAIL"
    fi
    printf "%s  %-24s %s\n" "$status" "${result_names[$i]}" "$(format_duration "${result_duration_ms[$i]}")"
    if [[ ${result_passed[$i]} -eq 0 ]]; then
      echo "  exit code: ${result_exit[$i]}"
      while IFS= read -r err_line; do
        [[ -n "$err_line" ]] && echo "  $err_line"
      done < <(get_failure_details "${result_log_files[$i]}")
    fi
  done
  echo ""
  echo "$passed_count passed, $failed_count failed, ${#result_names[@]} run"
} >"$REPORT_PATH"

echo "======== summary ========"
for i in "${!result_names[@]}"; do
  if [[ ${result_passed[$i]} -eq 1 ]]; then
    printf "PASS  %-24s %s\n" "${result_names[$i]}" "$(format_duration "${result_duration_ms[$i]}")"
  else
    printf "FAIL  %-24s %s\n" "${result_names[$i]}" "$(format_duration "${result_duration_ms[$i]}")"
    echo "      exit code: ${result_exit[$i]}"
    while IFS= read -r err_line; do
      [[ -n "$err_line" ]] && echo "      $err_line"
    done < <(get_failure_details "${result_log_files[$i]}")
  fi
done

for log_file in "${result_log_files[@]}"; do
  rm -f "$log_file"
done

echo ""
echo "$passed_count passed, $failed_count failed  ($(format_duration "$total_ms"))"
echo "Report: $REPORT_PATH"

if [[ $failed_count -gt 0 ]]; then
  exit 1
fi
exit 0
