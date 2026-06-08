// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

func IsDestinationEnabled(dest service.Destination) bool {
	return ptr.Deref(dest.Enabled, true)
}
