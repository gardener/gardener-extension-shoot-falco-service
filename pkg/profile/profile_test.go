// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/profile/v1alpha1"
)

var (
	now           = time.Now().Round(time.Second)
	dummyVer      = "0.0.0"
	falcoVersions = map[string]FalcoVersion{
		dummyVer: {
			Classification: "supported",
			ExpirationDate: &now,
			Version:        dummyVer,
		},
	}
	falcosidekickVersions = map[string]Version{
		dummyVer: {
			Classification: "supported",
			ExpirationDate: &now,
			Version:        dummyVer,
		},
	}
	falcoctlVersions = map[string]Version{
		dummyVer: {
			Classification: "supported",
			ExpirationDate: &now,
			Version:        dummyVer,
		},
	}
	images = map[string]Image{
		dummyVer: {
			Repository: "test/test",
			Tag:        dummyVer,
			Version:    dummyVer,
		},
	}
)

var _ = Describe("Falco profile manager", func() {
	var profileManager *FalcoProfileManager
	BeforeEach(func() {
		profileManager = GetDummyFalcoProfileManager(&falcoVersions, &images, &falcosidekickVersions, &images, &falcoctlVersions, &images)
		Expect(profileManager).ToNot(BeNil(), "profileManager should not be nil")
	})

	Context("getting falco version", func() {
		It("can get correct versions", func() {
			Expect(*profileManager.GetFalcoVersions()).To(Equal(falcoVersions))
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
			Expect(*profileManager.GetFalcosidekickVersions()).To(Equal(falcosidekickVersions))
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
			Expect(*profileManager.GetFalcoctlVersions()).To(Equal(falcoctlVersions))
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

	Context("updateEvent with multiple profiles", func() {
		var profileManager *FalcoProfileManager

		BeforeEach(func() {
			// Start with empty state
			emptyFalcoVersions := make(map[string]FalcoVersion)
			emptyFalcosidekickVersions := make(map[string]Version)
			emptyFalcoctlVersions := make(map[string]Version)
			emptyImages := make(map[string]Image)
			profileManager = GetDummyFalcoProfileManager(&emptyFalcoVersions, &emptyImages, &emptyFalcosidekickVersions, &emptyImages, &emptyFalcoctlVersions, &emptyImages)
			// Initialize the falcoProfiles map which is needed by updateEvent
			profileManager.falcoProfiles = make(map[string]*v1alpha1.FalcoProfile)
		})

		It("should correctly add a single profile to state", func() {
			// Create first profile with specific versions
			expirationDate1 := "2025-12-31T23:59:59Z"
			profile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "1.0.0",
								RulesVersion:   "1.0.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "2.0.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.0.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.0.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
						},
					},
				},
			}

			// Update event with profile1
			profileManager.updateEvent(profile1)

			// Verify falco versions
			falcoVersions := profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(1))
			Expect((*falcoVersions)["1.0.0"].Version).To(Equal("1.0.0"))
			Expect((*falcoVersions)["1.0.0"].Classification).To(Equal("supported"))
			Expect((*falcoVersions)["1.0.0"].RulesVersion).To(Equal("1.0.0"))
			Expect((*falcoVersions)["1.0.0"].ExpirationDate).ToNot(BeNil())

			// Verify falco images
			falcoImage := profileManager.GetFalcoImage("1.0.0")
			Expect(falcoImage).ToNot(BeNil())
			Expect(falcoImage.Version).To(Equal("1.0.0"))
			Expect(falcoImage.Repository).To(Equal("falcosecurity/falco"))
			Expect(falcoImage.Tag).To(Equal("1.0.0"))

			// Verify falcosidekick versions
			falcosidekickVersions := profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(1))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			Expect((*falcosidekickVersions)["2.0.0"].Classification).To(Equal("supported"))

			// Verify falcosidekick images
			falcosidekickImage := profileManager.GetFalcosidekickImage("2.0.0")
			Expect(falcosidekickImage).ToNot(BeNil())
			Expect(falcosidekickImage.Version).To(Equal("2.0.0"))
			Expect(falcosidekickImage.Repository).To(Equal("falcosecurity/falcosidekick"))
			Expect(falcosidekickImage.Tag).To(Equal("2.0.0"))
		})

		It("should correctly merge multiple profiles into state", func() {
			// Create first profile
			expirationDate1 := "2025-12-31T23:59:59Z"
			profile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "1.0.0",
								RulesVersion:   "1.0.0",
							},
							{
								Classification: "deprecated",
								ExpirationDate: nil,
								Version:        "1.1.0",
								RulesVersion:   "1.1.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "2.0.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.0.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.0.0",
							},
							{
								Version:    "1.1.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.1.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
						},
					},
				},
			}

			// Create second profile with different versions
			expirationDate2 := "2026-06-30T23:59:59Z"
			profile2 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile2",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "preview",
								ExpirationDate: &expirationDate2,
								Version:        "1.2.0",
								RulesVersion:   "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "preview",
								ExpirationDate: &expirationDate2,
								Version:        "2.1.0",
							},
							{
								Classification: "supported",
								ExpirationDate: nil,
								Version:        "2.2.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.2.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.1.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.1.0",
							},
							{
								Version:    "2.2.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.2.0",
							},
						},
					},
				},
			}

			// Add first profile
			profileManager.updateEvent(profile1)

			// Verify initial state
			falcoVersions := profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(2))
			Expect((*falcoVersions)["1.0.0"].Version).To(Equal("1.0.0"))
			Expect((*falcoVersions)["1.1.0"].Version).To(Equal("1.1.0"))

			falcosidekickVersions := profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(1))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))

			// Add second profile
			profileManager.updateEvent(profile2)

			// Verify merged state - should have versions from both profiles
			falcoVersions = profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(3))
			Expect((*falcoVersions)["1.0.0"].Version).To(Equal("1.0.0"))
			Expect((*falcoVersions)["1.0.0"].Classification).To(Equal("supported"))
			Expect((*falcoVersions)["1.1.0"].Version).To(Equal("1.1.0"))
			Expect((*falcoVersions)["1.1.0"].Classification).To(Equal("deprecated"))
			Expect((*falcoVersions)["1.2.0"].Version).To(Equal("1.2.0"))
			Expect((*falcoVersions)["1.2.0"].Classification).To(Equal("preview"))

			falcosidekickVersions = profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(3))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			Expect((*falcosidekickVersions)["2.1.0"].Version).To(Equal("2.1.0"))
			Expect((*falcosidekickVersions)["2.2.0"].Version).To(Equal("2.2.0"))
			Expect((*falcosidekickVersions)["2.2.0"].ExpirationDate).To(BeNil())

			// Verify all images are present
			Expect(profileManager.GetFalcoImage("1.0.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcoImage("1.1.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcoImage("1.2.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcosidekickImage("2.0.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcosidekickImage("2.1.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcosidekickImage("2.2.0")).ToNot(BeNil())
		})

		It("should correctly update a single profile by removing falcosidekick versions and images", func() {
			// Create profile with two falcosidekick versions and images
			expirationDate := "2025-12-31T23:59:59Z"
			profile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate,
								Version:        "2.0.0",
							},
							{
								Classification: "deprecated",
								ExpirationDate: nil,
								Version:        "2.1.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
							{
								Version:    "2.1.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.1.0",
							},
						},
					},
				},
			}

			// Add initial profile with two falcosidekick versions
			profileManager.updateEvent(profile1)

			// Verify initial state has two falcosidekick versions and images
			falcosidekickVersions := profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(2))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			Expect((*falcosidekickVersions)["2.0.0"].Classification).To(Equal("supported"))
			Expect((*falcosidekickVersions)["2.1.0"].Version).To(Equal("2.1.0"))
			Expect((*falcosidekickVersions)["2.1.0"].Classification).To(Equal("deprecated"))

			falcosidekickImage20 := profileManager.GetFalcosidekickImage("2.0.0")
			Expect(falcosidekickImage20).ToNot(BeNil())
			Expect(falcosidekickImage20.Version).To(Equal("2.0.0"))
			Expect(falcosidekickImage20.Repository).To(Equal("falcosecurity/falcosidekick"))
			Expect(falcosidekickImage20.Tag).To(Equal("2.0.0"))

			falcosidekickImage21 := profileManager.GetFalcosidekickImage("2.1.0")
			Expect(falcosidekickImage21).ToNot(BeNil())
			Expect(falcosidekickImage21.Version).To(Equal("2.1.0"))
			Expect(falcosidekickImage21.Repository).To(Equal("falcosecurity/falcosidekick"))
			Expect(falcosidekickImage21.Tag).To(Equal("2.1.0"))

			// Update profile1 with only one falcosidekick version and image
			updatedProfile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate,
								Version:        "2.0.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
						},
					},
				},
			}

			// Update the profile
			profileManager.updateEvent(updatedProfile1)

			// Verify state now only contains one falcosidekick version and one image
			falcosidekickVersions = profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(1))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			Expect((*falcosidekickVersions)["2.0.0"].Classification).To(Equal("supported"))

			// Version 2.1.0 should no longer exist
			_, exists := (*falcosidekickVersions)["2.1.0"]
			Expect(exists).To(BeFalse())

			// Verify only one image remains
			falcosidekickImage := profileManager.GetFalcosidekickImage("2.0.0")
			Expect(falcosidekickImage).ToNot(BeNil())
			Expect(falcosidekickImage.Version).To(Equal("2.0.0"))
			Expect(falcosidekickImage.Repository).To(Equal("falcosecurity/falcosidekick"))
			Expect(falcosidekickImage.Tag).To(Equal("2.0.0"))

			// Image for version 2.1.0 should no longer exist
			Expect(profileManager.GetFalcosidekickImage("2.1.0")).To(BeNil())
		})

		It("should correctly remove versions when updating a profile with fewer entries", func() {
			// Create initial profile with multiple versions
			expirationDate := "2025-12-31T23:59:59Z"
			profile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate,
								Version:        "1.0.0",
								RulesVersion:   "1.0.0",
							},
							{
								Classification: "deprecated",
								ExpirationDate: nil,
								Version:        "1.1.0",
								RulesVersion:   "1.1.0",
							},
							{
								Classification: "preview",
								ExpirationDate: &expirationDate,
								Version:        "1.2.0",
								RulesVersion:   "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate,
								Version:        "2.0.0",
							},
							{
								Classification: "deprecated",
								ExpirationDate: nil,
								Version:        "2.1.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.0.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.0.0",
							},
							{
								Version:    "1.1.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.1.0",
							},
							{
								Version:    "1.2.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
							{
								Version:    "2.1.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.1.0",
							},
						},
					},
				},
			}

			// Add initial profile
			profileManager.updateEvent(profile1)

			// Verify initial state
			falcoVersions := profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(3))
			Expect(profileManager.GetFalcoImage("1.0.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcoImage("1.1.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcoImage("1.2.0")).ToNot(BeNil())

			falcosidekickVersions := profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(2))
			Expect(profileManager.GetFalcosidekickImage("2.0.0")).ToNot(BeNil())
			Expect(profileManager.GetFalcosidekickImage("2.1.0")).ToNot(BeNil())

			// Update profile1 with fewer versions (remove 1.1.0 and 1.2.0 for falco, remove 2.1.0 for falcosidekick)
			updatedProfile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate,
								Version:        "1.0.0",
								RulesVersion:   "1.0.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate,
								Version:        "2.0.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.0.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.0.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
						},
					},
				},
			}

			// Update the profile
			profileManager.updateEvent(updatedProfile1)

			// Verify that removed versions are no longer present
			falcoVersions = profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(1))
			Expect((*falcoVersions)["1.0.0"].Version).To(Equal("1.0.0"))
			Expect(profileManager.GetFalcoImage("1.1.0")).To(BeNil())
			Expect(profileManager.GetFalcoImage("1.2.0")).To(BeNil())

			falcosidekickVersions = profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(1))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			Expect(profileManager.GetFalcosidekickImage("2.1.0")).To(BeNil())
		})

		It("should correctly handle deleteEvent", func() {
			// Create two profiles
			expirationDate1 := "2025-12-31T23:59:59Z"
			profile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "1.0.0",
								RulesVersion:   "1.0.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "2.0.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.0.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.0.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
						},
					},
				},
			}

			expirationDate2 := "2026-06-30T23:59:59Z"
			profile2 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile2",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "preview",
								ExpirationDate: &expirationDate2,
								Version:        "1.2.0",
								RulesVersion:   "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "preview",
								ExpirationDate: &expirationDate2,
								Version:        "2.1.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.2.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.1.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.1.0",
							},
						},
					},
				},
			}

			// Add both profiles
			profileManager.updateEvent(profile1)
			profileManager.updateEvent(profile2)

			// Verify both profiles exist
			falcoVersions := profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(2))
			Expect((*falcoVersions)["1.0.0"].Version).To(Equal("1.0.0"))
			Expect((*falcoVersions)["1.2.0"].Version).To(Equal("1.2.0"))

			falcosidekickVersions := profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(2))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			Expect((*falcosidekickVersions)["2.1.0"].Version).To(Equal("2.1.0"))

			// Delete profile1
			profileManager.deleteEvent("profile1")

			// Verify only profile2's versions remain
			falcoVersions = profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(1))
			Expect((*falcoVersions)["1.2.0"].Version).To(Equal("1.2.0"))
			Expect(profileManager.GetFalcoImage("1.0.0")).To(BeNil())
			Expect(profileManager.GetFalcoImage("1.2.0")).ToNot(BeNil())

			falcosidekickVersions = profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(1))
			Expect((*falcosidekickVersions)["2.1.0"].Version).To(Equal("2.1.0"))
			Expect(profileManager.GetFalcosidekickImage("2.0.0")).To(BeNil())
			Expect(profileManager.GetFalcosidekickImage("2.1.0")).ToNot(BeNil())

			// Delete profile2
			profileManager.deleteEvent("profile2")

			// Verify all versions are removed
			falcoVersions = profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(0))
			Expect(profileManager.GetFalcoImage("1.2.0")).To(BeNil())

			falcosidekickVersions = profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(0))
			Expect(profileManager.GetFalcosidekickImage("2.1.0")).To(BeNil())
		})

		It("should handle overlapping versions between multiple profiles", func() {
			// Create two profiles with overlapping versions
			expirationDate1 := "2025-12-31T23:59:59Z"
			profile1 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile1",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "1.0.0",
								RulesVersion:   "1.0.0",
							},
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "1.1.0",
								RulesVersion:   "1.1.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate1,
								Version:        "2.0.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.0.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.0.0",
							},
							{
								Version:    "1.1.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.1.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
						},
					},
				},
			}

			// profile2 has overlapping version 1.1.0 with different classification
			expirationDate2 := "2026-06-30T23:59:59Z"
			profile2 := &v1alpha1.FalcoProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "profile2",
				},
				Spec: v1alpha1.Spec{
					Versions: v1alpha1.Versions{
						Falco: []v1alpha1.FalcoVersion{
							{
								Classification: "deprecated", // Different classification for same version
								ExpirationDate: &expirationDate2,
								Version:        "1.1.0",
								RulesVersion:   "1.1.0",
							},
							{
								Classification: "preview",
								ExpirationDate: &expirationDate2,
								Version:        "1.2.0",
								RulesVersion:   "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.FalcosidekickVersion{
							{
								Classification: "supported",
								ExpirationDate: &expirationDate2,
								Version:        "2.0.0", // Same version as profile1
							},
							{
								Classification: "preview",
								ExpirationDate: &expirationDate2,
								Version:        "2.1.0",
							},
						},
					},
					Images: v1alpha1.Images{
						Falco: []v1alpha1.ImageSpec{
							{
								Version:    "1.1.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.1.0",
							},
							{
								Version:    "1.2.0",
								Repository: "falcosecurity/falco",
								Tag:        "1.2.0",
							},
						},
						Falcosidekick: []v1alpha1.ImageSpec{
							{
								Version:    "2.0.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.0.0",
							},
							{
								Version:    "2.1.0",
								Repository: "falcosecurity/falcosidekick",
								Tag:        "2.1.0",
							},
						},
					},
				},
			}

			// Add both profiles
			profileManager.updateEvent(profile1)
			profileManager.updateEvent(profile2)

			// Verify merged state - all versions from both profiles should be present
			falcoVersions := profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(3))
			Expect((*falcoVersions)["1.0.0"].Version).To(Equal("1.0.0"))
			Expect((*falcoVersions)["1.1.0"].Version).To(Equal("1.1.0"))
			// Version 1.1.0 appears in both profiles - could have either classification
			// since rebuild() iterates over map without guaranteed order
			Expect((*falcoVersions)["1.1.0"].Classification).To(Or(Equal("supported"), Equal("deprecated")))
			Expect((*falcoVersions)["1.2.0"].Version).To(Equal("1.2.0"))

			falcosidekickVersions := profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(2))
			// Version 2.0.0 appears in both profiles
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			Expect((*falcosidekickVersions)["2.1.0"].Version).To(Equal("2.1.0"))

			// Delete profile2
			profileManager.deleteEvent("profile2")

			// After deletion, only profile1's versions should remain
			falcoVersions = profileManager.GetFalcoVersions()
			Expect(*falcoVersions).To(HaveLen(2))
			Expect((*falcoVersions)["1.0.0"].Version).To(Equal("1.0.0"))
			Expect((*falcoVersions)["1.1.0"].Version).To(Equal("1.1.0"))
			// Version 1.1.0 should now have profile1's classification
			Expect((*falcoVersions)["1.1.0"].Classification).To(Equal("supported"))
			// Version 1.2.0 should be gone
			_, exists := (*falcoVersions)["1.2.0"]
			Expect(exists).To(BeFalse())

			falcosidekickVersions = profileManager.GetFalcosidekickVersions()
			Expect(*falcosidekickVersions).To(HaveLen(1))
			Expect((*falcosidekickVersions)["2.0.0"].Version).To(Equal("2.0.0"))
			// Version 2.1.0 should be gone
			_, exists = (*falcosidekickVersions)["2.1.0"]
			Expect(exists).To(BeFalse())
		})
	})
})
