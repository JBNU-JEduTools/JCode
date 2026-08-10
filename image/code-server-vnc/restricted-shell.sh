#!/bin/bash
# Usability guard only; Kubernetes mounts and securityContext are the boundary.
cd() {
  if [ -z "$WORKSPACE_ROOT" ]; then
    builtin cd "$@"
    return
  fi
  local target root
  if [ -z "$1" ] || [ "$1" = "~" ]; then
    target="$WORKSPACE_ROOT"
  else
    target=$(realpath -m "$1" 2>/dev/null || echo "$1")
  fi
  if [[ "$target" != /* ]]; then
    target=$(realpath -m "$(pwd)/$target" 2>/dev/null || echo "$(pwd)/$target")
  fi
  root=$(realpath -m "$WORKSPACE_ROOT" 2>/dev/null || echo "$WORKSPACE_ROOT")
  case "$target" in
    "$root"|"$root"/*) ;;
    *) echo "접근 제한: 워크스페이스 밖으로 이동할 수 없습니다."; return 1 ;;
  esac
  builtin cd "$@"
}
if [ -n "$WORKSPACE_ROOT" ]; then
  export HOME="$WORKSPACE_ROOT"
fi
export -f cd
