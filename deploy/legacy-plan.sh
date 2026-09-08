#!/usr/bin/env bash
# shellcheck disable=SC2034 # 함수 호출자가 읽는 출력 변수입니다.

load_legacy_plan_entry() {
  local plan=$1 environment=$2 namespace=$3
  action=$(jq -er --arg environment "$environment" --arg namespace "$namespace" \
    '.environments[$environment][$namespace].action' "$plan") || {
    echo "metadata-less legacy namespace is missing from the $environment migration plan: $namespace" >&2
    return 2
  }

  reason=
  course_id=
  plan_target_namespace=
  use_vnc=
  session_policy=
  case "$action" in
    quarantine)
      reason=$(jq -er --arg environment "$environment" --arg namespace "$namespace" \
        '.environments[$environment][$namespace].reason' "$plan")
      ;;
    migrate)
      course_id=$(jq -er --arg environment "$environment" --arg namespace "$namespace" \
        '.environments[$environment][$namespace].course_id' "$plan")
      plan_target_namespace=$(jq -er --arg environment "$environment" --arg namespace "$namespace" \
        '.environments[$environment][$namespace].target_namespace' "$plan")
      use_vnc=$(jq -r --arg environment "$environment" --arg namespace "$namespace" \
        '.environments[$environment][$namespace].use_vnc' "$plan")
      [[ "$use_vnc" == true || "$use_vnc" == false ]] || {
        echo "use_vnc must be true or false for $namespace" >&2
        return 2
      }
      session_policy=$(jq -er --arg environment "$environment" --arg namespace "$namespace" \
        '.environments[$environment][$namespace].session_policy' "$plan")
      ;;
    *)
      echo "unsupported migration action for $namespace: $action" >&2
      return 2
      ;;
  esac
}
