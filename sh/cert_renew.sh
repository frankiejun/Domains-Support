#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 批量续约 SSL 证书脚本
# 读取域名文件（一行一个域名），逐个调用 certbot renew
# ============================================================

# ===================== 用户配置区 ============================

# 每次续约之间的等待秒数（避免触发 rate limit）
INTERVAL_SECONDS=5

# 续约成功后是否 reload nginx
RELOAD_NGINX=true

# nginx reload 命令
NGINX_RELOAD_CMD="systemctl reload nginx"

# ===================== 以下无需修改 ==========================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; }

TOTAL=0
SUCCESS=0
FAILED=0
SKIPPED=0
NEED_RELOAD=false

usage() {
	echo "用法: $0 [选项] <域名文件>"
	echo ""
	echo "选项:"
	echo "  --dry-run    模拟运行，不实际续约"
	echo "  -h, --help   显示帮助"
	echo ""
	echo "域名文件格式: 一行一个域名"
	echo ""
	echo "示例:"
	echo "  $0 domains.txt"
	echo "  $0 --dry-run domains.txt"
	exit 0
}

DRY_RUN=false
DOMAIN_FILE=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run)
		DRY_RUN=true
		shift
		;;
	-h | --help) usage ;;
	-*)
		err "未知选项: $1"
		exit 1
		;;
	*)
		DOMAIN_FILE="$1"
		shift
		;;
	esac
done

if [ -z "$DOMAIN_FILE" ]; then
	err "请指定域名文件"
	echo ""
	usage
fi

if [ ! -f "$DOMAIN_FILE" ]; then
	err "文件不存在: $DOMAIN_FILE"
	exit 1
fi

if ! command -v certbot &>/dev/null; then
	err "certbot 未安装"
	exit 1
fi

renew_one() {
	local domain="$1"
	local cert_name=""

	cert_name=$(certbot certificates 2>/dev/null | awk -v d="$domain" '
        /Certificate Name:/ { cur = $3 }
        /Domains:/ && index($0, d) {
            split($0, parts, "Domains:")
            rest = parts[2]
            n = split(rest, items)
            for (i = 1; i <= n; i++) {
                if (items[i] == d) { print cur; exit }
            }
        }
    ')

	if [ -z "$cert_name" ]; then
		warn "$domain: 未在 certbot 中找到对应证书，跳过"
		SKIPPED=$((SKIPPED + 1))
		return 1
	fi

	local cmd="certbot renew --cert-name $cert_name"
	if [ "$DRY_RUN" = true ]; then
		cmd="$cmd --dry-run"
	fi

	info "$domain (证书名: $cert_name): 开始续约..."
	local output
	if output=$($cmd 2>&1); then
		if echo "$output" | grep -q "renewed\|Congratulations"; then
			ok "$domain: 续约成功"
			SUCCESS=$((SUCCESS + 1))
			NEED_RELOAD=true
		elif echo "$output" | grep -q "not yet due\|No renewals were attempted"; then
			info "$domain: 证书未到期，无需续约"
			SKIPPED=$((SKIPPED + 1))
		else
			ok "$domain: 续约完成"
			SUCCESS=$((SUCCESS + 1))
		fi
	else
		err "$domain: 续约失败"
		echo "$output" | grep -i 'error\|fail\|rate' | head -3 | while read -r line; do
			err "  $line"
		done
		FAILED=$((FAILED + 1))
		return 1
	fi
}

main() {
	echo ""
	info "批量续约 SSL 证书"
	if [ "$DRY_RUN" = true ]; then
		warn "模拟运行模式 (--dry-run)，不会实际续约"
	fi
	info "域名文件: $DOMAIN_FILE"
	info "续约间隔: ${INTERVAL_SECONDS}s"
	echo ""

	local domains=()
	while IFS= read -r line; do
		line=$(echo "$line" | xargs)
		[ -z "$line" ] && continue
		[[ "$line" == \#* ]] && continue
		domains+=("$line")
	done <"$DOMAIN_FILE"

	if [ "${#domains[@]}" -eq 0 ]; then
		err "域名文件为空"
		exit 1
	fi

	info "共 ${#domains[@]} 个域名待处理"
	echo ""

	for domain in "${domains[@]}"; do
		TOTAL=$((TOTAL + 1))
		renew_one "$domain" || true
		if [ "$TOTAL" -lt "${#domains[@]}" ]; then
			sleep "$INTERVAL_SECONDS"
		fi
	done

	if [ "$NEED_RELOAD" = true ] && [ "$RELOAD_NGINX" = true ] && [ "$DRY_RUN" = false ]; then
		echo ""
		info "续约成功，reload nginx..."
		if $NGINX_RELOAD_CMD 2>/dev/null; then
			ok "nginx reload 成功"
		else
			warn "nginx reload 失败，请手动执行: $NGINX_RELOAD_CMD"
		fi
	fi

	echo ""
	echo "========================================"
	info "执行完毕"
	info "总计: ${TOTAL}  成功: ${SUCCESS}  失败: ${FAILED}  跳过: ${SKIPPED}"
	echo "========================================"

	if [ "$FAILED" -gt 0 ]; then
		exit 1
	fi
}

main
