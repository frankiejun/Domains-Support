#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Cloudflare DNS A 记录 IP 批量替换脚本（多账号版）
# 遍历所有账号下所有域名的 A 记录，将等于 OLD_IP 的改为 NEW_IP
# ============================================================

# ===================== 用户配置区 ============================

# 多账号配置
# 格式: "API_TOKEN|EMAIL(可选，Token认证可留空)"
# 在 Cloudflare Dashboard -> My Profile -> API Tokens 创建 Token
ACCOUNTS=(
    "cf-api-token-1|user1@example.com"
    "cf-api-token-2|"
    "cf-api-token-3|admin@example.com"
)

# 要查找的旧 IP（A 记录的 content 等于此值时会被修改）
OLD_IP=""

# 要替换成的新 IP
NEW_IP=""

# ===================== 以下无需修改 ==========================

API_BASE="https://api.cloudflare.com/client/v4"

# 全局统计
TOTAL_SCANNED=0
TOTAL_MATCHED=0
TOTAL_UPDATED=0
TOTAL_FAILED=0

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

info() { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; }
account_header() { echo -e "${MAGENTA}[ACCOUNT]${NC} $1"; }

# 检查必要变量
check_config() {
	local missing=0
	if [ "${#ACCOUNTS[@]}" -eq 0 ]; then
		err "ACCOUNTS 未配置任何账号"
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

	# 验证每个账号格式
	local i=1
	for entry in "${ACCOUNTS[@]}"; do
		local token="${entry%%|*}"
		if [ -z "$token" ]; then
			err "ACCOUNTS[$i] 的 API Token 为空"
			missing=1
		fi
		i=$((i + 1))
	done
	if [ "$missing" -eq 1 ]; then
		echo ""
		err "账号格式: \"API_TOKEN|EMAIL(可选)\""
		exit 1
	fi
}

# 发起 Cloudflare API 请求
cf_api() {
	local token="$1"
	local email="$2"
	local method="$3"
	local path="$4"
	local data="${5:-}"

	local url="${API_BASE}${path}"
	local args=(-s -X "$method" -H "Authorization: Bearer $token" -H "Content-Type: application/json")

	if [ -n "$email" ]; then
		args+=(-H "X-Auth-Email: $email")
	fi

	if [ -n "$data" ]; then
		args+=(-d "$data")
	fi

	curl "${args[@]}" "$url"
}

# 验证单个账号的 Token
verify_token() {
	local token="$1"
	local email="$2"

	local test_resp
	test_resp=$(cf_api "$token" "$email" GET "/user/tokens/verify")
	local test_success
	test_success=$(echo "$test_resp" | jq -r '.success // false')

	if [ "$test_success" != "true" ]; then
		local test_err
		test_err=$(echo "$test_resp" | jq -r '.errors[0].message // "Token 无效"')
		echo "$test_err"
		return 1
	fi

	echo "${email:-unknown}"
	return 0
}

# 列出所有 zone（处理分页）
list_all_zones() {
	local token="$1"
	local email="$2"
	local page=1
	local total_pages=1
	local all_zones=()

	while [ "$page" -le "$total_pages" ]; do
		local resp
		resp=$(cf_api "$token" "$email" GET "/zones?per_page=50&page=$page")
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
	local token="$1"
	local email="$2"
	local zone_id="$3"
	local zone_name="$4"
	local page=1
	local total_pages=1
	local all_records=()

	while [ "$page" -le "$total_pages" ]; do
		local resp
		resp=$(cf_api "$token" "$email" GET "/zones/${zone_id}/dns_records?type=A&per_page=100&page=$page")
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

# 更新 A 记录（保留原记录的 proxied 与 ttl 设置）
update_a_record() {
	local token="$1"
	local email="$2"
	local zone_id="$3"
	local record_id="$4"
	local name="$5"
	local current_ip="$6"
	local proxied="$7"
	local ttl="$8"

	# proxied 仅接受 true/false，异常值兜底为 false
	if [ "$proxied" != "true" ] && [ "$proxied" != "false" ]; then
		proxied="false"
	fi

	# ttl 必须是正整数，异常值兜底为 1（auto）
	if ! [[ "$ttl" =~ ^[0-9]+$ ]]; then
		ttl=1
	fi

	local payload
	payload=$(jq -n \
		--arg type "A" \
		--arg name "$name" \
		--arg content "$NEW_IP" \
		--argjson ttl "$ttl" \
		--argjson proxied "$proxied" \
		'{type: $type, name: $name, content: $content, ttl: $ttl, proxied: $proxied}')

	local resp
	resp=$(cf_api "$token" "$email" PUT "/zones/${zone_id}/dns_records/${record_id}" "$payload")
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

# 处理单个账号
process_account() {
	local index="$1"
	local entry="$2"

	local token="${entry%%|*}"
	local email="${entry#*|}"

	# 如果 email 和 token 相同，说明没有 | 分隔，设为空
	[ "$email" = "$entry" ] && email=""

	echo ""
	account_header "账号 #${index}"
	account_header "Token: ${token:0:8}...${token: -4}  Email: ${email:-N/A}"

	# 验证 Token
	info "  验证 API Token..."
	local verify_result
	if ! verify_result=$(verify_token "$token" "$email"); then
		err "  API Token 验证失败: $verify_result"
		return 1
	fi
	ok "  API Token 验证通过 (账户: ${verify_result})"
	echo ""

	# 账号级统计
	local acc_scanned=0
	local acc_matched=0
	local acc_updated=0
	local acc_failed=0

	# 获取所有 zone
	info "  获取所有域名(zone)列表..."
	local zones=()
	while IFS= read -r zone; do
		[ -n "$zone" ] && zones+=("$zone")
	done < <(list_all_zones "$token" "$email")

	if [ "${#zones[@]}" -eq 0 ]; then
		warn "  未找到任何域名(zone)"
		return 0
	fi
	ok "  共找到 ${#zones[@]} 个域名(zone)"
	echo ""

	# 遍历每个 zone
	for zone_json in "${zones[@]}"; do
		local zone_id zone_name
		zone_id=$(echo "$zone_json" | jq -r '.id')
		zone_name=$(echo "$zone_json" | jq -r '.name')

		info "  处理域名: ${zone_name} (${zone_id})"

		# 获取该 zone 下所有 A 记录
		local records=()
		while IFS= read -r record; do
			[ -n "$record" ] && records+=("$record")
		done < <(list_all_a_records "$token" "$email" "$zone_id" "$zone_name" 2>/dev/null || echo "")

		if [ "${#records[@]}" -eq 0 ]; then
			info "    没有 A 记录，跳过"
			continue
		fi

		# 遍历 A 记录
		for record_json in "${records[@]}"; do
			local record_id record_name record_content record_proxied record_ttl
			record_id=$(echo "$record_json" | jq -r '.id')
			record_name=$(echo "$record_json" | jq -r '.name')
			record_content=$(echo "$record_json" | jq -r '.content')
			record_proxied=$(echo "$record_json" | jq -r '.proxied // false')
			record_ttl=$(echo "$record_json" | jq -r '.ttl // 1')

			acc_scanned=$((acc_scanned + 1))
			TOTAL_SCANNED=$((TOTAL_SCANNED + 1))

			if [ "$record_content" != "$OLD_IP" ]; then
				continue
			fi

			acc_matched=$((acc_matched + 1))
			TOTAL_MATCHED=$((TOTAL_MATCHED + 1))
			info "    匹配 A 记录: ${record_name} -> ${record_content} (proxied: ${record_proxied}, ttl: ${record_ttl})"

			if update_a_record "$token" "$email" "$zone_id" "$record_id" "$record_name" "$record_content" "$record_proxied" "$record_ttl"; then
				acc_updated=$((acc_updated + 1))
				TOTAL_UPDATED=$((TOTAL_UPDATED + 1))
				ok "    已更新: ${record_name}  ${OLD_IP} -> ${NEW_IP} (proxied: ${record_proxied}, ttl: ${record_ttl})"
			else
				acc_failed=$((acc_failed + 1))
				TOTAL_FAILED=$((TOTAL_FAILED + 1))
			fi
		done
	done

	# 账号汇总
	echo ""
	info "  账号 #${index} 汇总:"
	info "    扫描 A 记录数: ${acc_scanned}"
	info "    匹配 OLD_IP 数: ${acc_matched}"
	ok "    成功更新数: ${acc_updated}"
	if [ "$acc_failed" -gt 0 ]; then
		err "    失败数: ${acc_failed}"
	fi

	return 0
}

main() {
	echo ""
	info "Cloudflare DNS A 记录 IP 批量替换脚本（多账号版）"
	info "查找 OLD_IP: ${OLD_IP}  ->  替换为 NEW_IP: ${NEW_IP}"
	info "配置账号数: ${#ACCOUNTS[@]}"
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

	local account_count="${#ACCOUNTS[@]}"
	local account_success=0
	local account_fail=0

	# 逐个处理账号
	for i in "${!ACCOUNTS[@]}"; do
		local idx=$((i + 1))
		if process_account "$idx" "${ACCOUNTS[$i]}"; then
			account_success=$((account_success + 1))
		else
			account_fail=$((account_fail + 1))
		fi
	done

	# 总汇总
	echo ""
	echo "========================================"
	info "全部执行完毕"
	info "账号统计: 成功 ${account_success} / 失败 ${account_fail} / 总计 ${account_count}"
	echo "----------------------------------------"
	info "全局统计:"
	info "  扫描 A 记录数:   ${TOTAL_SCANNED}"
	info "  匹配 OLD_IP 数:  ${TOTAL_MATCHED}"
	ok "  成功更新数:     ${TOTAL_UPDATED}"
	if [ "$TOTAL_FAILED" -gt 0 ]; then
		err "  失败数:         ${TOTAL_FAILED}"
	fi
	echo "========================================"
}

main "$@"
