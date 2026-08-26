#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

echo "> Spell check"

MISSPELL_BIN="$1"

"$MISSPELL_BIN" -error ./docs ./pkg ./cmd ./crds ./rules ./charts
