//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
// Code generated by deepcopy-gen. DO NOT EDIT.

package config

import (
	v1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Configuration) DeepCopyInto(out *Configuration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.Falco != nil {
		in, out := &in.Falco, &out.Falco
		*out = new(Falco)
		(*in).DeepCopyInto(*out)
	}
	if in.HealthCheckConfig != nil {
		in, out := &in.HealthCheckConfig, &out.HealthCheckConfig
		*out = new(v1alpha1.HealthCheckConfig)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Configuration.
func (in *Configuration) DeepCopy() *Configuration {
	if in == nil {
		return nil
	}
	out := new(Configuration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Configuration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Falco) DeepCopyInto(out *Falco) {
	*out = *in
	if in.PriorityClassName != nil {
		in, out := &in.PriorityClassName, &out.PriorityClassName
		*out = new(string)
		**out = **in
	}
	if in.CertificateLifetime != nil {
		in, out := &in.CertificateLifetime, &out.CertificateLifetime
		*out = new(v1.Duration)
		**out = **in
	}
	if in.CertificateRenewAfter != nil {
		in, out := &in.CertificateRenewAfter, &out.CertificateRenewAfter
		*out = new(v1.Duration)
		**out = **in
	}
	if in.TokenLifetime != nil {
		in, out := &in.TokenLifetime, &out.TokenLifetime
		*out = new(v1.Duration)
		**out = **in
	}
	if in.DefaultEventLogger != nil {
		in, out := &in.DefaultEventLogger, &out.DefaultEventLogger
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Falco.
func (in *Falco) DeepCopy() *Falco {
	if in == nil {
		return nil
	}
	out := new(Falco)
	in.DeepCopyInto(out)
	return out
}
