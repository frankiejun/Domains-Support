#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
DOMAIN_ARG="${2:-}"

REPO_URL="https://github.com/frankiejun/Domains-Support.git"
BRANCH="vps-beta"
SRC_DIR="$(pwd)/Domains-Support"
DEPLOY_DIR="/deploy/domains-support"
WWW_DIR="/var/www/domains-support"
NGINX_CONF="/etc/nginx/conf.d/ds.conf"
PM2_NAME="ds"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root 权限运行"
    exit 1
  fi
}

install_pkg() {
  local pkg="$1"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "$pkg"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$pkg"
  else
    echo "未知包管理器，无法安装 $pkg"
    exit 1
  fi
}

ensure_dep() {
  command -v nginx >/dev/null 2>&1 || install_pkg nginx
  command -v certbot >/dev/null 2>&1 || install_pkg certbot
  command -v node >/dev/null 2>&1 || install_pkg nodejs
  command -v npm >/dev/null 2>&1 || install_pkg npm
  if ! command -v pm2 >/dev/null 2>&1; then
    npm install -g pm2
  fi
  command -v git >/dev/null 2>&1 || install_pkg git
}

clone_repo() {
  if [ -d "$SRC_DIR/.git" ]; then
    echo "源码已存在：$SRC_DIR"
    (cd "$SRC_DIR" && git fetch && git checkout "$BRANCH" && git pull --rebase)
  else
    git clone "$REPO_URL" "$SRC_DIR"
    (cd "$SRC_DIR" && git checkout "$BRANCH")
  fi
}

prepare_dirs() {
  mkdir -p "$WWW_DIR"
  mkdir -p "$DEPLOY_DIR"
}

copy_websites() {
  rsync -av --delete "$SRC_DIR/websites/" "$WWW_DIR/"
}

build_project() {
  (cd "$SRC_DIR" && npm install && npm run build)
}

sync_deploy() {
  rsync -av --delete "$SRC_DIR/public/" "$DEPLOY_DIR/public/"
  rsync -av --delete "$SRC_DIR/dist/" "$DEPLOY_DIR/dist/"
  rsync -av --delete "$SRC_DIR/server/" "$DEPLOY_DIR/server/"
  rsync -av --delete "$SRC_DIR/node_modules/" "$DEPLOY_DIR/node_modules/"
  rsync -av "$SRC_DIR/package.json" "$DEPLOY_DIR/package.json"
  mkdir -p "$DEPLOY_DIR/data"
}

start_pm2() {
  (cd "$DEPLOY_DIR" && pm2 start server/index.js --name "$PM2_NAME")
  pm2 save
}

stop_pm2() {
  pm2 stop "$PM2_NAME" || true
  pm2 delete "$PM2_NAME" || true
}

write_nginx_conf() {
  local domain="${1:-domain.com}"
  cat > "$NGINX_CONF" <<EOF
server {
  listen 443;
  server_name ${domain};

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 3600s;
  }
}
EOF
  nginx -t
  systemctl reload nginx
}

do_install() {
  need_root
  ensure_dep
  clone_repo
  prepare_dirs
  copy_websites
  build_project
  sync_deploy
  start_pm2
  write_nginx_conf "${DOMAIN_ARG:-domain.com}"
  echo "安装完成：访问 https://${DOMAIN_ARG:-domain.com}/"
}

do_update() {
  need_root
  if [ ! -d "$SRC_DIR" ]; then
    echo "未找到源码目录：$SRC_DIR，请先执行 install"
    exit 1
  fi
  (cd "$SRC_DIR" && git stash || true)
  (cd "$SRC_DIR" && git pull)
  stop_pm2
  build_project
  sync_deploy
  start_pm2
  echo "更新完成"
}

do_uninstall() {
  need_root
  stop_pm2
  rm -rf "$DEPLOY_DIR"
  rm -rf "$WWW_DIR"
  rm -f "$NGINX_CONF"
  systemctl reload nginx || true
  echo "卸载完成"
}

case "$ACTION" in
  install) do_install ;;
  update) do_update ;;
  uninstall) do_uninstall ;;
  *)
    echo "用法: $0 [install|update|uninstall] [domain(optional for install)]"
    exit 1
    ;;
esac

