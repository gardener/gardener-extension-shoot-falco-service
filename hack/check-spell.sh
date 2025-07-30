#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

echo "> Spell check"

MISSPELL_BIN="$1"

"$MISSPELL_BIN" -error ./docs ./pkg ./cmd ./crds ./rules ./charts
