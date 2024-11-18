// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/profile/v1alpha1"
)

var (
	now      = time.Now().Round(time.Second)
	dummyVer = "0.0.0"
	versions = map[string]Version{
		dummyVer: {
			Classification: "supported",
			ExpirationDate: &now,
			Version:        dummyVer,
		},
	}
	images = map[string]Image{
		dummyVer: {
			Repository:   "test/test",
			Tag:          dummyVer,
			Architectrue: "testarch",
			Version:      dummyVer,
		},
	}
)

var _ = Describe("Falco profile manager", func() {
	var profileManager *FalcoProfileManager
	BeforeEach(func() {
		profileManager = GetDummyFalcoProfileManager(&versions, &images, &versions, &images, &versions, &images)
		Expect(profileManager).ToNot(BeNil(), "profileManager should not be nil")
	})

	Context("getting falco version", func() {
		It("can get correct versions", func() {
			Expect(*profileManager.GetFalcoVersions()).To(Equal(versions))
		})
	})

	Context("getting falco images", func() {
		It("can get correct images", func() {
			Expect(*profileManager.GetFalcoImage(dummyVer)).To(Equal(images[dummyVer]))
			Expect(profileManager.GetFalcoImage("0.0.1")).To(BeNil())
		})
	})

	Context("getting falcosidekick version", func() {
		It("can get correct versions", func() {
			Expect(*profileManager.GetFalcosidekickVersions()).To(Equal(versions))
		})
	})

	Context("getting falcosidekick images", func() {
		It("can get correct images", func() {
			Expect(*profileManager.GetFalcosidekickImage(dummyVer)).To(Equal(images[dummyVer]))
			Expect(profileManager.GetFalcosidekickImage("0.0.1")).To(BeNil())
		})
	})

	Context("getting falcoctl version", func() {
		It("can get correct versions", func() {
			Expect(*profileManager.GetFalcoctlVersions()).To(Equal(versions))
		})
	})

	Context("getting falcoctl images", func() {
		It("can get correct images", func() {
			Expect(*profileManager.GetFalcoctlImage(dummyVer)).To(Equal(images[dummyVer]))
			Expect(profileManager.GetFalcoctlImage("0.0.1")).To(BeNil())
		})
	})

	Context("getting expiration date", func() {
		It("can get correct expiration date", func() {
			nowStr := now.Format(time.RFC3339)
			version := v1alpha1.FalcoVersion{
				Classification: "supported",
				ExpirationDate: &nowStr,
				Version:        dummyVer,
			}
			expir := getExpirationDate(version)
			Expect(expir).ToNot(BeNil())
			prev, _ := time.Parse(time.RFC3339, nowStr)
			Expect(*expir).To(Equal(prev))
		})
	})
})
