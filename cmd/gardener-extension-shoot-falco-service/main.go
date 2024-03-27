// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	runtimelog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"github.com/gardener/gardener-extension-falco/cmd/gardener-extension-shoot-falco-service/app"
)

func main() {

	ctx := signals.SetupSignalHandler()

	if err := app.NewControllerManagerCommand(ctx).ExecuteContext(ctx); err != nil {
		runtimelog.Log.Error(err, "Error executing the main controller command")
		os.Exit(1)
	}
}
