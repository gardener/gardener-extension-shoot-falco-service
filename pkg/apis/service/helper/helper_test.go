// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/helper"
)

var _ = Describe("Helper", func() {
	DescribeTable("IsDestinationEnabled",
		func(enabled *bool, expected bool) {
			dest := service.Destination{Name: "logging", Enabled: enabled}
			Expect(helper.IsDestinationEnabled(dest)).To(Equal(expected))
		},
		Entry("nil defaults to true", nil, true),
		Entry("explicit true", ptr.To(true), true),
		Entry("explicit false", ptr.To(false), false),
	)
})
