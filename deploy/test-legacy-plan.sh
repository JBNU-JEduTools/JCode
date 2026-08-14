#!/usr/bin/env bash
set -euo pipefail

plan=${1:-deploy/legacy-namespace-plan.json}
# shellcheck source=deploy/legacy-plan.sh
source "$(dirname "$0")/legacy-plan.sh"

load_legacy_plan_entry "$plan" dev jcode-dev-1
[[ "$action" == quarantine && -n "$reason" && -z "$course_id" ]]

load_legacy_plan_entry "$plan" dev jcode-realtest2-1
[[ "$action" == migrate ]]
[[ "$course_id" == 6 ]]
[[ "$plan_target_namespace" == jcode-dev-realtest2-1 ]]
[[ "$use_vnc" == false && "$session_policy" == recreate && -z "$reason" ]]

load_legacy_plan_entry "$plan" dev jcode-test2502-1
[[ "$action" == migrate && "$course_id" == 1 ]]
[[ "$plan_target_namespace" == jcode-dev-test2502-1 ]]

load_legacy_plan_entry "$plan" prod jcode-jct-1
[[ "$action" == quarantine && -n "$reason" && -z "$course_id" ]]
