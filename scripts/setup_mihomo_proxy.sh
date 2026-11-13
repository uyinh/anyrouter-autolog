#!/usr/bin/env bash
# 通过 mihomo 拉取订阅、启动本地代理并逐个探测节点。
# 环境变量:
#   CHECKIN_PROXY_URL       已配置的直接代理地址（优先使用）
#   PROXY_SUBSCRIPTION_URL  订阅链接（必填才启用）
#   PROXY_TEST_URL          节点探测目标，默认 https://agentrouter.org/login
#   PROXY_MAX_PROBES        最多切换测试的节点数，默认 5
#   PROXY_REQUIRED          true 时探测失败则退出 1
#   PROXY_PORT              本地 mixed-port，默认 7890
#   PROXY_API_PORT          mihomo external-controller 端口，默认 9090

set -euo pipefail

probe_login_page() {
	local proxy_url="$1"
	local body
	body=$(curl -fsS -x "${proxy_url}" --max-time 12 \
		-A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36" \
		"${PROXY_TEST_URL}" 2>/dev/null) || return 1
	[[ ${#body} -gt 500 ]] || return 1
	[[ "${body}" == *"/assets/index-"* ]] || return 1
	[[ "${body}" != *"Access Verification"* ]] || return 1
	[[ "${body}" != *"slide to verify"* ]] || return 1
	return 0
}

if [[ -n "${CHECKIN_PROXY_URL:-}" ]]; then
	PROXY_TEST_URL="${DIRECT_PROXY_TEST_URL:-https://agentrouter.org}"
	PROXY_TEST_URL="${PROXY_TEST_URL%/}/login"
	if probe_login_page "${CHECKIN_PROXY_URL}"; then
		echo "[SUCCESS] Direct proxy returned a real login page"
		if [[ -n "${GITHUB_ENV:-}" ]]; then
			echo "CHECKIN_PROXY_URL=${CHECKIN_PROXY_URL}" >> "${GITHUB_ENV}"
		fi
		exit 0
	fi
	echo "[FAILED] Direct proxy is blocked by WAF or unreachable: ${PROXY_TEST_URL}"
	exit 1
fi

if [[ -z "${PROXY_SUBSCRIPTION_URL:-}" ]]; then
	echo "[INFO] PROXY_SUBSCRIPTION_URL not set, skip proxy setup"
	exit 0
fi

PROXY_DIR="${RUNNER_TEMP:-/tmp}/checkin-proxy"
PROXY_PORT="${PROXY_PORT:-7890}"
PROXY_API_PORT="${PROXY_API_PORT:-9090}"
PROXY_TEST_URL="${PROXY_TEST_URL:-https://agentrouter.org/login}"
PROXY_MAX_PROBES="${PROXY_MAX_PROBES:-5}"
MIHOMO_VERSION="${MIHOMO_VERSION:-v1.19.0}"
PROXY_REQUIRED="${PROXY_REQUIRED:-false}"
PROXY_API="http://127.0.0.1:${PROXY_API_PORT}"

mkdir -p "${PROXY_DIR}"
cd "${PROXY_DIR}"

echo "[INFO] Downloading mihomo ${MIHOMO_VERSION}..."
ARCHIVE="mihomo-linux-amd64-${MIHOMO_VERSION}.gz"
if ! curl --retry 3 --retry-delay 5 --retry-all-errors -fsSL -o "${ARCHIVE}" \
	"https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${ARCHIVE}"; then
	echo "[WARN] Failed to download mihomo ${MIHOMO_VERSION}, skip proxy setup"
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
fi
gunzip -f "${ARCHIVE}"
chmod +x "mihomo-linux-amd64-${MIHOMO_VERSION}"
MIHOMO_BIN="${PROXY_DIR}/mihomo-linux-amd64-${MIHOMO_VERSION}"

cat > config.yaml <<EOF
mixed-port: ${PROXY_PORT}
external-controller: 127.0.0.1:${PROXY_API_PORT}
allow-lan: false
ipv6: false
mode: rule
log-level: warning
unified-delay: true

proxy-providers:
  subscription:
    type: http
    url: "${PROXY_SUBSCRIPTION_URL}"
    interval: 3600
    path: ./subscription.yaml
    health-check:
      enable: true
      interval: 300
      url: https://www.gstatic.com/generate_204

proxy-groups:
  - name: CHECKIN
    type: select
    use:
      - subscription

rules:
  - MATCH,CHECKIN
EOF

echo "[INFO] Starting mihomo on 127.0.0.1:${PROXY_PORT}..."
nohup "${MIHOMO_BIN}" -d "${PROXY_DIR}" -f config.yaml > mihomo.log 2>&1 &
echo $! > mihomo.pid

PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
READY=false

echo "[INFO] Waiting for mihomo API..."
for attempt in $(seq 1 30); do
	if curl -fsS "${PROXY_API}/proxies/CHECKIN" -o "${PROXY_DIR}/nodes.json" 2>/dev/null; then
		break
	fi
	sleep 1
done

NODE_COUNT=0
if [[ -s "${PROXY_DIR}/nodes.json" ]]; then
	NODE_COUNT=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1])).get('all') or []))" "${PROXY_DIR}/nodes.json" 2>/dev/null || echo 0)
fi
echo "[INFO] Subscription has ${NODE_COUNT} node(s), probing up to ${PROXY_MAX_PROBES}"

PROBED=0
while IFS= read -r node; do
	[[ -n "${node}" ]] || continue
	if [[ ${PROBED} -ge ${PROXY_MAX_PROBES} ]]; then
		break
	fi
	PROBED=$((PROBED + 1))
	echo "[INFO] Probing node ${PROBED}/${PROXY_MAX_PROBES}: ${node}"
	body=$(printf '%s' "${node}" | python3 -c 'import json,sys; print(json.dumps({"name": sys.stdin.read()}))')
	if ! curl -fsS -X PUT "${PROXY_API}/proxies/CHECKIN" -H 'Content-Type: application/json' -d "${body}" >/dev/null 2>&1; then
		echo "[WARN] Failed to switch node: ${node}"
		continue
	fi
	if probe_login_page "${PROXY_URL}"; then
		echo "[SUCCESS] Node passed login-page check: ${node}"
		READY=true
		break
	fi
	echo "[WARN] Node blocked by WAF or unreachable: ${node}"
done < <(python3 -c "import json,sys; print('\n'.join(json.load(open(sys.argv[1])).get('all') or []))" "${PROXY_DIR}/nodes.json" 2>/dev/null || true)

if [[ "${READY}" != "true" ]]; then
	echo "[FAILED] No node returned a real login page within ${PROXY_MAX_PROBES} attempts"
	tail -n 30 mihomo.log || true
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		kill "$(cat mihomo.pid)" 2>/dev/null || true
		exit 1
	fi
	# 保留代理，让浏览器撞到 WAF 页后快速失败并报告原因
	echo "[WARN] Keeping proxy with the last probed node for diagnosis"
	if [[ -n "${GITHUB_ENV:-}" ]]; then
		echo "CHECKIN_PROXY_URL=${PROXY_URL}" >> "${GITHUB_ENV}"
	fi
	exit 0
fi

echo "[SUCCESS] Proxy is ready: ${PROXY_URL}"
echo "[INFO] Proxy is scoped to CHECKIN_PROXY_URL (browser/python only, not global HTTP_PROXY)"
if [[ -n "${GITHUB_ENV:-}" ]]; then
	echo "CHECKIN_PROXY_URL=${PROXY_URL}" >> "${GITHUB_ENV}"
fi
