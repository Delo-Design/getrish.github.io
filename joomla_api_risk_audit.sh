#!/usr/bin/env bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[0m'

if [[ -n "${NO_COLOR:-}" ]]; then
  GREEN=''
  RED=''
  YELLOW=''
  CYAN=''
  WHITE=''
fi

set -o pipefail

SCAN_ROOT="${1:-/var/www}"
SEPARATOR='────────────────────────────────────────────────────────────'
RECORD_SEPARATOR=$'\037'

usage() {
  cat <<'EOF'
Проверка локальной конфигурации Joomla API

Использование:
  sudo ./joomla_api_risk_audit.sh [путь]

По умолчанию проверяется /var/www. Скрипт только читает файлы Joomla
и выполняет SELECT-запросы к локальной MariaDB.

Для отключения цветов:
  NO_COLOR=1 sudo ./joomla_api_risk_audit.sh
EOF
}

fail() {
  printf '%b\n' "${RED}$1${WHITE}" >&2
  exit 1
}

print_value() {
  local label="$1"
  local value="$2"
  local color="${3:-$GREEN}"

  printf '%s %b%s%b\n' "$label" "$color" "$value" "$WHITE"
}

php_config_string() {
  local name="$1"
  local config_file="$2"

  sed -nE "s/^[[:space:]]*(public[[:space:]]+)?\\\$${name}[[:space:]]*=[[:space:]]*'([^']*)'.*/\\2/p" "$config_file" |
    head -n 1
}

php_config_scalar() {
  local name="$1"
  local config_file="$2"

  sed -nE "s/^[[:space:]]*(public[[:space:]]+)?\\\$${name}[[:space:]]*=[[:space:]]*([^;]+);.*/\\2/p" "$config_file" |
    head -n 1 |
    sed -E "s/^[[:space:]]+|[[:space:]]+$//g; s/^'//; s/'$//"
}

read_joomla_version() {
  local version_file="$1"

  sed -nE 's@.*<version>[[:space:]]*([0-9]+(\.[0-9]+)+)[[:space:]]*</version>.*@\1@p' "$version_file" |
    head -n 1
}

version_is_affected() {
  local version="$1"
  local first

  first=$(printf '%s\n%s\n' '4.0.0' "$version" | sort -V | head -n 1)
  [[ "$first" == '4.0.0' ]] || return 1

  first=$(printf '%s\n%s\n' "$version" '5.4.7' | sort -V | head -n 1)
  if [[ "$first" == "$version" ]]; then
    return 0
  fi

  first=$(printf '%s\n%s\n' '6.0.0' "$version" | sort -V | head -n 1)
  [[ "$first" == '6.0.0' ]] || return 1

  first=$(printf '%s\n%s\n' "$version" '6.1.2' | sort -V | head -n 1)
  [[ "$first" == "$version" ]]
}

bool_label() {
  case "${1,,}" in
    1 | true | yes | on)
      printf '%s' 'включён'
      ;;
    *)
      printf '%s' 'выключен'
      ;;
  esac
}

is_local_database_host() {
  case "${1,,}" in
    '' | localhost | localhost:* | 127.0.0.1 | 127.0.0.1:* | ::1 | \[::1\] | /*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

join_by_comma() {
  local first=1
  local value

  for value in "$@"; do
    if ((first)); then
      printf '%s' "$value"
      first=0
    else
      printf ', %s' "$value"
    fi
  done
}

audit_database() {
  local site_path="$1"
  local config_file="$2"
  local db_name
  local db_host
  local db_prefix
  local extensions_table
  local profiles_table
  local users_table
  local user_group_map_table
  local usergroups_table
  local query
  local query_output
  local row_type
  local folder
  local element
  local enabled
  local user_id
  local username
  local blocked
  local groups
  local unblocked_users=0
  local token_auth='не найден'
  local basic_auth='не найден'
  local user_token='не найден'
  local active_token_count=0
  local blocked_token_count=0
  local -a enabled_webservices=()
  local -a disabled_webservices=()
  local -a other_auth=()
  local -a active_token_users=()
  local -a blocked_token_users=()

  db_name="$(php_config_string 'db' "$config_file")"
  db_host="$(php_config_string 'host' "$config_file")"
  db_prefix="$(php_config_string 'dbprefix' "$config_file")"

  if [[ -z "$db_name" || -z "$db_prefix" ]]; then
    print_value 'База данных:' 'не удалось прочитать db или dbprefix из configuration.php' "$RED"
    return
  fi

  if [[ ! "$db_name" =~ ^[A-Za-z0-9_.-]+$ || ! "$db_prefix" =~ ^[A-Za-z0-9_]+$ ]]; then
    print_value 'База данных:' 'имя базы или префикс таблиц имеют неожиданный формат' "$RED"
    return
  fi

  if ! is_local_database_host "$db_host"; then
    print_value 'База данных:' "внешний сервер ${db_host}; плагины и токены не проверялись" "$YELLOW"
    return
  fi

  extensions_table="${db_prefix}extensions"
  profiles_table="${db_prefix}user_profiles"
  users_table="${db_prefix}users"
  user_group_map_table="${db_prefix}user_usergroup_map"
  usergroups_table="${db_prefix}usergroups"

  query="
SELECT CONCAT('PLUGIN', CHAR(31), folder, CHAR(31), element, CHAR(31), enabled)
FROM \`${extensions_table}\`
WHERE type = 'plugin'
  AND (folder IN ('webservices', 'api-authentication') OR (folder = 'user' AND element = 'token'))
ORDER BY folder, element;

SELECT CONCAT('USERS', CHAR(31), COUNT(*))
FROM \`${users_table}\`
WHERE block = 0;

SELECT CONCAT(
  'TOKEN_USER', CHAR(31), u.id, CHAR(31), u.username, CHAR(31), u.block, CHAR(31),
  COALESCE(GROUP_CONCAT(DISTINCT g.title ORDER BY g.title SEPARATOR ', '), '')
)
FROM \`${users_table}\` AS u
INNER JOIN \`${profiles_table}\` AS token_profile
  ON token_profile.user_id = u.id
  AND token_profile.profile_key = 'joomlatoken.token'
  AND token_profile.profile_value <> ''
INNER JOIN \`${profiles_table}\` AS enabled_profile
  ON enabled_profile.user_id = u.id
  AND enabled_profile.profile_key = 'joomlatoken.enabled'
  AND LOWER(TRIM(enabled_profile.profile_value)) IN ('1', 'true', 'yes', 'on')
LEFT JOIN \`${user_group_map_table}\` AS map ON map.user_id = u.id
LEFT JOIN \`${usergroups_table}\` AS g ON g.id = map.group_id
GROUP BY u.id, u.username, u.block
ORDER BY u.id;
"

  if ! query_output=$(mariadb --batch --raw --skip-column-names --database="$db_name" -e "$query" 2>/dev/null); then
    print_value 'База данных:' "не удалось прочитать ${db_name} через локальное подключение MariaDB" "$RED"
    return
  fi

  while IFS="$RECORD_SEPARATOR" read -r row_type folder element enabled; do
    [[ -n "$row_type" ]] || continue

    case "$row_type" in
      PLUGIN)
        case "$folder" in
          webservices)
            if [[ "$enabled" == '1' ]]; then
              enabled_webservices+=("$element")
            else
              disabled_webservices+=("$element")
            fi
            ;;
          api-authentication)
            case "$element" in
              token)
                [[ "$enabled" == '1' ]] && token_auth='включена' || token_auth='выключена'
                ;;
              basic)
                [[ "$enabled" == '1' ]] && basic_auth='включена' || basic_auth='выключена'
                ;;
              *)
                [[ "$enabled" == '1' ]] && other_auth+=("${element} (включена)") || other_auth+=("${element} (выключена)")
                ;;
            esac
            ;;
          user)
            [[ "$enabled" == '1' ]] && user_token='включён' || user_token='выключен'
            ;;
        esac
        ;;
      USERS)
        unblocked_users="$folder"
        ;;
    esac
  done <<< "$query_output"

  while IFS="$RECORD_SEPARATOR" read -r row_type user_id username blocked groups; do
    [[ "$row_type" == 'TOKEN_USER' ]] || continue

    if [[ "$blocked" == '0' ]]; then
      active_token_count=$((active_token_count + 1))
      active_token_users+=("${username} (ID ${user_id}; группы: ${groups:-не указаны})")
    else
      blocked_token_count=$((blocked_token_count + 1))
      blocked_token_users+=("${username} (ID ${user_id}; группы: ${groups:-не указаны})")
    fi
  done <<< "$query_output"

  print_value 'Локальная база данных:' "$db_name" "$CYAN"

  if ((${#enabled_webservices[@]})); then
    print_value 'Включённые плагины webservices:' "$(join_by_comma "${enabled_webservices[@]}")" "$GREEN"
  else
    print_value 'Включённые плагины webservices:' 'нет' "$YELLOW"
  fi

  if ((${#disabled_webservices[@]})); then
    print_value 'Выключенные плагины webservices:' "$(join_by_comma "${disabled_webservices[@]}")" "$YELLOW"
  fi

  print_value 'Token Auth:' "$token_auth" "$([[ "$token_auth" == 'включена' ]] && printf '%s' "$GREEN" || printf '%s' "$YELLOW")"
  print_value 'Basic Auth:' "$basic_auth" "$([[ "$basic_auth" == 'включена' ]] && printf '%s' "$YELLOW" || printf '%s' "$GREEN")"
  print_value 'Плагин управления пользовательскими токенами:' "$user_token" "$([[ "$user_token" == 'включён' ]] && printf '%s' "$GREEN" || printf '%s' "$YELLOW")"

  if ((${#other_auth[@]})); then
    print_value 'Сторонние плагины API-аутентификации:' "$(join_by_comma "${other_auth[@]}")" "$YELLOW"
  else
    print_value 'Сторонние плагины API-аутентификации:' 'не найдены' "$GREEN"
  fi

  print_value 'Незаблокированные пользователи Joomla:' "$unblocked_users" "$CYAN"
  print_value 'Пользователи с включённым API-токеном:' "$active_token_count" "$([[ "$active_token_count" -gt 0 ]] && printf '%s' "$YELLOW" || printf '%s' "$GREEN")"

  for username in "${active_token_users[@]}"; do
    printf '  - %b%s%b\n' "$YELLOW" "$username" "$WHITE"
  done

  if ((blocked_token_count)); then
    print_value 'Заблокированные пользователи с включённым токеном:' "$blocked_token_count" "$YELLOW"
    for username in "${blocked_token_users[@]}"; do
      printf '  - %b%s%b\n' "$YELLOW" "$username" "$WHITE"
    done
  fi
}

audit_site() {
  local version_file="$1"
  local site_path="${version_file%/administrator/manifests/files/joomla.xml}"
  local config_file="${site_path}/configuration.php"
  local api_entry="${site_path}/api/index.php"
  local version
  local major
  local cors
  local cors_origin

  version="$(read_joomla_version "$version_file")"

  printf '\n%s\n' "$SEPARATOR"
  print_value 'Сайт:' "$site_path" "$CYAN"

  if [[ -z "$version" ]]; then
    print_value 'Версия Joomla:' 'не удалось определить' "$RED"
    return
  fi

  major="${version%%.*}"
  print_value 'Версия Joomla:' "$version" "$GREEN"

  if version_is_affected "$version"; then
    print_value 'Затронута уязвимостями, исправленными в Joomla 5.4.8/6.1.3:' 'да' "$YELLOW"
    print_value 'Обновление:' 'до 5.4.8, 6.1.3 или более новой поддерживаемой версии' "$YELLOW"
  else
    print_value 'Затронута уязвимостями, исправленными в Joomla 5.4.8/6.1.3:' 'нет' "$GREEN"
  fi

  if [[ ! "$major" =~ ^[0-9]+$ ]] || ((10#$major < 4)); then
    print_value 'Проверка Joomla API:' 'не применяется к Joomla ниже версии 4' "$GREEN"
    return
  fi

  if [[ -f "$api_entry" ]]; then
    print_value 'Приложение Joomla API:' "найдено (${api_entry})" "$GREEN"
  else
    print_value 'Приложение Joomla API:' "${api_entry} не найден" "$YELLOW"
  fi

  if [[ ! -f "$config_file" ]]; then
    print_value 'Конфигурация Joomla:' "${config_file} не найден" "$RED"
    return
  fi

  cors="$(php_config_scalar 'cors' "$config_file")"
  cors_origin="$(php_config_string 'cors_allow_origin' "$config_file")"
  print_value 'CORS:' "$(bool_label "$cors")" "$([[ "$(bool_label "$cors")" == 'включён' ]] && printf '%s' "$YELLOW" || printf '%s' "$GREEN")"

  if [[ "$(bool_label "$cors")" == 'включён' ]]; then
    print_value 'Разрешённый CORS Origin:' "${cors_origin:-*}" "$CYAN"
  fi

  audit_database "$site_path" "$config_file"
}

if [[ "${1:-}" == '-h' || "${1:-}" == '--help' ]]; then
  usage
  exit 0
fi

[[ "$EUID" -eq 0 ]] || fail 'Для проверки всех сайтов и локальной MariaDB запустите скрипт от root.'
[[ -d "$SCAN_ROOT" ]] || fail "Папка для проверки не найдена: ${SCAN_ROOT}"

for command_name in find sed head sort mariadb; do
  command -v "$command_name" >/dev/null 2>&1 || fail "Не найдена обязательная команда: ${command_name}"
done

printf '%b\n' "Проверка локальной конфигурации ${CYAN}Joomla API${WHITE}"
print_value 'Путь поиска:' "$SCAN_ROOT" "$CYAN"
printf '%s\n' 'Скрипт не изменяет сайты и выполняет только SELECT-запросы к MariaDB.'

mapfile -d '' -t VERSION_FILES < <(
  find "$SCAN_ROOT" -xdev -type f -path '*/administrator/manifests/files/joomla.xml' -print0 2>/dev/null |
    sort -z
)

if ((${#VERSION_FILES[@]} == 0)); then
  printf '\n%b\n' "${YELLOW}Установки Joomla не найдены.${WHITE}"
  exit 0
fi

for version_file in "${VERSION_FILES[@]}"; do
  audit_site "$version_file"
done

printf '\n%s\n' "$SEPARATOR"
print_value 'Найдено установок Joomla:' "${#VERSION_FILES[@]}" "$CYAN"
printf '%s\n' 'Доступность /api из Интернета не проверялась; показана локальная конфигурация Joomla.'
printf '%s\n' 'Наличие токена само по себе не подтверждает эксплуатацию: итог зависит от ACL пользователя.'
