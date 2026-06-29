#!/bin/bash
# JCode Restricted Shell
# 학생이 워크스페이스 루트 상위로 이동하는 것을 제한합니다.
# WORKSPACE_ROOT 환경변수가 설정된 경우에��� 제한이 적용됩니다.

# cd 명령어 오버라이드
cd() {
  if [ -z "$WORKSPACE_ROOT" ]; then
    builtin cd "$@"
    return
  fi

  # 대상 경로 계산
  local target
  if [ -z "$1" ] || [ "$1" = "~" ]; then
    target="$WORKSPACE_ROOT"
  else
    target=$(realpath -m "$1" 2>/dev/null || echo "$1")
  fi

  # 절대 경로로 변환
  if [[ "$target" != /* ]]; then
    target=$(realpath -m "$(pwd)/$target" 2>/dev/null || echo "$(pwd)/$target")
  fi

  # 워크스페이스 루트 밖이면 차단
  if [[ "$target" != "$WORKSPACE_ROOT"* ]]; then
    echo "접근 제한: 워크스페이스 밖으로 이동할 수 없습니다."
    return 1
  fi

  builtin cd "$@"
}

# HOME을 워크스페이스 루트로 설정
if [ -n "$WORKSPACE_ROOT" ]; then
  export HOME="$WORKSPACE_ROOT"
fi

export -f cd
