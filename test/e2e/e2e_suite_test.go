/*
Copyright 2025 Stakater.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ctrl "sigs.k8s.io/controller-runtime"
	crzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

	_ "github.com/stakater-ab/mto-extension-openbao/test/utils"
)

// OperatorNS is the namespace primitive CRs are created in for the e2e
// specs. Sourced from $OPERATOR_NS (set by `make test-e2e`).
var OperatorNS string

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting openbao-config-operator suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	ctrl.SetLogger(crzap.New(crzap.UseDevMode(true)))

	OperatorNS = os.Getenv("OPERATOR_NS")
	Expect(OperatorNS).NotTo(BeEmpty(), "set OPERATOR_NS in make test-e2e")
})
