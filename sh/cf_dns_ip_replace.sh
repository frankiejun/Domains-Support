#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Cloudflare DNS A 记录 IP 批量替换脚本
# 遍历所有域名的 A 记录，将等于 OLD_IP 的改为 NEW_IP
# ============================================================

# ===================== 用户配置区 ============================

# Cloudflare API Token（需拥有 DNS 编辑权限）
# 在 Cloudflare Dashboard -> My Profile -> API Tokens 创建
CF_API_TOKEN=""

# Cloudflare 账户邮箱（仅当使用 API Key 认证时需要，Token 认证可留空）
CF_EMAIL=""

# 要查找的旧 IP（A 记录的 content 等于此值时会被修改）
OLD_IP=""

# 要替换成的新 IP
NEW_IP=""

# ===================== 以下无需修改 ==========================

API_BASE="https://api.cloudflare.com/client/v4"

TOTAL_SCANNED=0
TOTAL_MATCHED=0
TOTAL_UPDATED=0
TOTAL_FAILED=0

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info() { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查必要变量
check_config() {
	local missing=0
	if [ -z "$CF_API_TOKEN" ]; then
		err "CF_API_TOKEN 未设置"
		missing=1
	fi
	if [ -z "$OLD_IP" ]; then
		err "OLD_IP 未设置"
		missing=1
	fi
	if [ -z "$NEW_IP" ]; then
		err "NEW_IP 未设置"
		missing=1
	fi
	if [ "$missing" -eq 1 ]; then
		echo ""
		err "请先在脚本开头的"用户配置区"设置必要变量"
		exit 1
	fi
}

# 发起 Cloudflare API 请求
cf_api() {
	local method="$1"
	local path="$2"
	local data="${3:-}"

	local url="${API_BASE}${path}"
	local args=(-s -X "$method" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json")

	if [ -n "$CF_EMAIL" ]; then
		args+=(-H "X-Auth-Email: $CF_EMAIL")
	fi

	if [ -n "$data" ]; then
		args+=(-d "$data")
	fi

	curl "${args[@]}" "$url"
}

# 列出所有 zone（处理分页）
list_all_zones() {
	local page=1
	local total_pages=1
	local all_zones=()

	while [ "$page" -le "$total_pages" ]; do
		local resp
		resp=$(cf_api GET "/zones?per_page=50&page=$page")
		local success
		success=$(echo "$resp" | jq -r '.success // false')

		if [ "$success" != "true" ]; then
			local err_msg
			err_msg=$(echo "$resp" | jq -r '.errors[0].message // "未知错误"')
			err "获取 zone 列表失败（第 $page 页）: $err_msg"
			return 1
		fi

		local page_zones
		page_zones=$(echo "$resp" | jq -c '.result[] // empty')
		while IFS= read -r zone; do
			[ -n "$zone" ] && all_zones+=("$zone")
		done <<<"$page_zones"

		total_pages=$(echo "$resp" | jq -r '.result_info.total_pages // 1')
		page=$((page + 1))
	done

	for zone in "${all_zones[@]}"; do
		echo "$zone"
	done
}

# 列出指定 zone 的所有 A 记录（处理分页）
list_all_a_records() {
	local zone_id="$1"
	local zone_name="$2"
	local page=1
	local total_pages=1
	local all_records=()

	while [ "$page" -le "$total_pages" ]; do
		local resp
		resp=$(cf_api GET "/zones/${zone_id}/dns_records?type=A&per_page=100&page=$page")
		local success
		success=$(echo "$resp" | jq -r '.success // false')

		if [ "$success" != "true" ]; then
			local err_msg
			err_msg=$(echo "$resp" | jq -r '.errors[0].message // "未知错误"')
			warn "获取 ${zone_name} 的 A 记录失败（第 $page 页）: $err_msg"
			return 1
		fi

		local page_records
		page_records=$(echo "$resp" | jq -c '.result[] // empty')
		while IFS= read -r record; do
			[ -n "$record" ] && all_records+=("$record")
		done <<<"$page_records"

		total_pages=$(echo "$resp" | jq -r '.result_info.total_pages // 1')
		page=$((page + 1))
	done

	for record in "${all_records[@]}"; do
		echo "$record"
	done
}

# 更新 A 记录
update_a_record() {
	local zone_id="$1"
	local record_id="$2"
	local name="$3"
	local current_ip="$4"

	local payload
	payload=$(jq -n \
		--arg type "A" \
		--arg name "$name" \
		--arg content "$NEW_IP" \
		--argjson ttl 1 \
		--argjson proxied false \
		'{type: $type, name: $name, content: $content, ttl: $ttl, proxied: $proxied}')

	local resp
	resp=$(cf_api PUT "/zones/${zone_id}/dns_records/${record_id}" "$payload")
	local success
	success=$(echo "$resp" | jq -r '.success // false')

	if [ "$success" = "true" ]; then
		return 0
	else
		local err_msg
		err_msg=$(echo "$resp" | jq -r '.errors[0].message // "未知错误"')
		err "更新失败: $err_msg"
		return 1
	fi
}

main() {
	echo ""
	info "Cloudflare DNS A 记录 IP 批量替换脚本"
	info "查找 OLD_IP: ${OLD_IP}  ->  替换为 NEW_IP: ${NEW_IP}"
	echo ""

	check_config

	# 检查依赖
	if ! command -v jq &>/dev/null; then
		err "需要 jq 命令，请先安装: apt install jq 或 brew install jq"
		exit 1
	fi
	if ! command -v curl &>/dev/null; then
		err "需要 curl 命令，请先安装"
		exit 1
	fi

	# 测试 API Token 有效性
	info "验证 API Token..."
	local test_resp
	test_resp=$(cf_api GET "/user/tokens/verify")
	local test_success
	test_success=$(echo "$test_resp" | jq -r '.success // false')
	if [ "$test_success" != "true" ]; then
		local test_err
		test_err=$(echo "$test_resp" | jq -r '.errors[0].message // "Token 无效"')
		err "API Token 验证失败: $test_err"
		exit 1
	fi
	ok "API Token 验证通过"
	echo ""

	# 获取所有 zone
	info "获取所有域名(zone)列表..."
	local zones=()
	while IFS= read -r zone; do
		[ -n "$zone" ] && zones+=("$zone")
	done < <(list_all_zones)

	if [ "${#zones[@]}" -eq 0 ]; then
		warn "未找到任何域名(zone)"
		exit 0
	fi
	ok "共找到 ${#zones[@]} 个域名(zone)"
	echo ""

	# 遍历每个 zone
	for zone_json in "${zones[@]}"; do
		local zone_id zone_name
		zone_id=$(echo "$zone_json" | jq -r '.id')
		zone_name=$(echo "$zone_json" | jq -r '.name')

		info "处理域名: ${zone_name} (${zone_id})"

		# 获取该 zone 下所有 A 记录
		local records=()
		while IFS= read -r record; do
			[ -n "$record" ] && records+=("$record")
		done < <(list_all_a_records "$zone_id" "$zone_name" 2>/dev/null || echo "")

		if [ "${#records[@]}" -eq 0 ]; then
			info "  没有 A 记录，跳过"
			continue
		fi

		# 遍历 A 记录
		for record_json in "${records[@]}"; do
			local record_id record_name record_content record_ttl record_proxied
			record_id=$(echo "$record_json" | jq -r '.id')
			record_name=$(echo "$record_json" | jq -r '.name')
			record_content=$(echo "$record_json" | jq -r '.content')
			record_ttl=$(echo "$record_json" | jq -r '.ttl')
			record_proxied=$(echo "$record_json" | jq -r '.proxied')

			TOTAL_SCANNED=$((TOTAL_SCANNED + 1))

			if [ "$record_content" != "$OLD_IP" ]; then
				continue
			fi

			TOTAL_MATCHED=$((TOTAL_MATCHED + 1))
			info "  匹配 A 记录: ${record_name} -> ${record_content}"

			if update_a_record "$zone_id" "$record_id" "$record_name" "$record_content"; then
				TOTAL_UPDATED=$((TOTAL_UPDATED + 1))
				ok "  已更新: ${record_name}  ${OLD_IP} -> ${NEW_IP}"
			else
				TOTAL_FAILED=$((TOTAL_FAILED + 1))
			fi
		done
	done

	# 汇总
	echo ""
	echo "========================================"
	info "执行完毕"
	info "扫描 A 记录数:   ${TOTAL_SCANNED}"
	info "匹配 OLD_IP 数:  ${TOTAL_MATCHED}"
	ok "成功更新数:     ${TOTAL_UPDATED}"
	if [ "$TOTAL_FAILED" -gt 0 ]; then
		err "失败数:         ${TOTAL_FAILED}"
	fi
	echo "========================================"
}

main "$@"
