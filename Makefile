# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= 0.0.1
# Must equal the GitHub repository name. Stakater's shared CI derives the image
# it advertises on the pull request and pulls back during e2e from the
# repository name alone, so an image pushed under any other name is one nothing
# downstream can find.
OPERATOR_NAME ?= openbao-config-operator
CATALOG_DIR_PATH ?= catalog
DOCKER_REPO_BASE ?= ghcr.io/stakater
ifeq ($(strip $(DOCKER_REPO_BASE)),)
DOCKER_REPO_BASE := ghcr.io/stakater
endif

# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# stakater.cloud/openbao-config-operator-bundle:$VERSION and stakater.cloud/openbao-config-operator-catalog:$VERSION.
IMAGE_TAG_BASE ?= $(DOCKER_REPO_BASE)/$(OPERATOR_NAME)

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)$(GIT_TAG)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Set the Operator SDK version to use. By default, what is installed on the system is used.
# This is useful for CI or a project to utilize a specific version of the operator-sdk toolkit.
OPERATOR_SDK_VERSION ?= v1.41.1
# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):v$(VERSION)$(GIT_TAG)
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
# Track the apiserver minor that the target OpenShift release ships (4.20 -> 1.33),
# so unit tests exercise the same API surface production does. Overridable so a
# skew run can point at another minor without editing this file.
ENVTEST_K8S_VERSION ?= 1.33.0

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

TEST_CLUSTER_NAME ?= e2e-test-cluster
ACTION ?= cluster

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

OPENBAO_NS   ?= openbao
OPERATOR_NS  ?= openbao-config-operator-system
VAULT_ADDR   ?= http://openbao.$(OPENBAO_NS).svc.cluster.local:8200
POLICY_FILE  ?= test/policies/obx-e2e-manage.hcl
TOKEN_SECRET ?= mto-openbao-token
TOKEN_KEY    ?= token

# Local/test VAULT_ADDR via port-forward (host can reach cluster svc)
VAULT_ADDR_LOCAL ?= http://127.0.0.1:18200

.PHONY: test-e2e
test-e2e:
	@echo "Running e2e with VAULT_ADDR=$(VAULT_ADDR_LOCAL)"
	@# 1) Port-forward OpenBao service -> localhost:18200
	@kubectl -n $(OPENBAO_NS) port-forward svc/openbao 18200:8200 >/tmp/pf.log 2>&1 & echo $$! > .pf.pid
	@# 2) Wait until the port responds (fail if it never does)
	@ok=0; \
	for i in $$(seq 1 60); do \
		if curl -sS -o /dev/null $(VAULT_ADDR_LOCAL)/v1/sys/health; then \
			echo "OpenBao reachable on 127.0.0.1:18200"; ok=1; break; \
		fi; \
		sleep 1; \
	done; \
	if [ $$ok -ne 1 ]; then \
		echo "ERROR: OpenBao not reachable on 127.0.0.1:18200 after 60s"; \
		kill $$(cat .pf.pid) >/dev/null 2>&1 || true; rm -f .pf.pid; \
		exit 1; \
	fi
	@# 2) Read limited token from Secret and run tests with env set
	@TOKEN=$$(kubectl -n $(OPERATOR_NS) get secret $(TOKEN_SECRET) \
		-o go-template='{{index .data "$(TOKEN_KEY)" | base64decode}}'); \
	if [ -z "$$TOKEN" ]; then echo "ERROR: empty VAULT_TOKEN from secret $(TOKEN_SECRET)"; \
	kill $$(cat .pf.pid) >/dev/null 2>&1 || true; rm -f .pf.pid; exit 1; fi; \
	VAULT_ADDR=$(VAULT_ADDR_LOCAL) VAULT_TOKEN="$$TOKEN" OPERATOR_NS=$(OPERATOR_NS) \
	OPENBAO_NS=$(OPENBAO_NS) OPENBAO_SVC=openbao OPENBAO_SCHEME=http OPENBAO_PORT=8200 \
	OPENBAO_TOKEN_SECRET=mto-openbao-token OPENBAO_TOKEN_KEY=token \
		go test ./test/e2e/ -v -ginkgo.v; \
	RC=$$?; \
	kill $$(cat .pf.pid) >/dev/null 2>&1 || true; rm -f .pf.pid; \
	if [ $$RC -ne 0 ]; then $(MAKE) e2e-diagnostics; fi; \
	exit $$RC

.PHONY: openbao-install
openbao-install: helm
	$(HELM) repo add openbao https://openbao.github.io/openbao-helm ;\
	$(HELM) repo update ;\
	$(HELM) upgrade openbao openbao/openbao --namespace $(OPENBAO_NS) --create-namespace --install --set server.dev.enabled=true

.PHONY: openbao-provision-creds
openbao-provision-creds:
	OPENBAO_NS=$(OPENBAO_NS) \
	OPERATOR_NS=$(OPERATOR_NS) \
	VAULT_ADDR=$(VAULT_ADDR) \
	VAULT_TOKEN=root \
	POLICY_NAME=obx-e2e-manage \
	POLICY_FILE=$(POLICY_FILE) \
	./hack/e2e/openbao/provision_credentials.sh

# Bootstraps the operator's own kubernetes-auth identity (mount, config,
# operator-manage policy, role). The operator then logs in with its
# ServiceAccount instead of reading a token from a Secret. Idempotent.
# VAULT_TOKEN=root matches the dev-mode openbao-install; production runs the
# script directly with a temp bootstrap token (see bootstrap-policy.hcl).
.PHONY: openbao-bootstrap-auth
openbao-bootstrap-auth:
	OPENBAO_NS=$(OPENBAO_NS) \
	OPERATOR_NS=$(OPERATOR_NS) \
	VAULT_ADDR=$(VAULT_ADDR) \
	VAULT_TOKEN=root \
	./hack/e2e/openbao/bootstrap_operator_auth.sh

.PHONY: operator-deploy
operator-deploy:
	kubectl create ns $(OPERATOR_NS) --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(OPERATOR_NS) apply -f hack/e2e/obx/rbac.yaml
	OPERATOR_IMAGE=$(OPERATOR_IMAGE) ./hack/apply_env_yaml.sh hack/e2e/obx/deploy.yaml.tmpl
	kubectl -n $(OPERATOR_NS) rollout status deploy/mto-openbao-extension --timeout=180s

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg GIT_USER=${GIT_USER} --build-arg GIT_TOKEN=${GIT_TOKEN} -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name openbao-config-operator-builder
	$(CONTAINER_TOOL) buildx use openbao-config-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm openbao-config-operator-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: load-image
load-image: ## Load local image into Kind cluster if it exists locally, otherwise it will be pulled
	$(MAKE) cluster ACTION=load-image

# Wait for the controller rollout, dumping cluster state to stdout if it stalls
# and retrying once after a clean restart.
#
# The dump goes to stdout rather than to files under e2e-logs/ on purpose: this
# runs in `deploy`, which is upstream of `test-e2e`, so a failure here aborts the
# job before any artifact-uploading step is reached. Printing means the evidence
# lands in the workflow log, where it survives regardless.
#
# The retry is not just defensive. A private image on a cold Kind node has no
# local layer to reuse, and one fixed window gives a slow pull no second chance;
# ImagePullBackOff also burns through a short window in two or three attempts.
define rollout-controller-with-retry
@bash -ceu '\
	ns="$(OPERATOR_NS)"; \
	dep="$(OPERATOR_NAME)-controller-manager"; \
	echo ">>> Waiting for rollout (90s fast path)..."; \
	if ! $(KUBECTL) -n "$$ns" rollout status deploy/"$$dep" --timeout=90s; then \
	  echo ">>> Rollout stalled - collecting debug info before restart"; \
	  echo "---- Deployment describe ----"; \
	  $(KUBECTL) -n "$$ns" describe deploy/"$$dep" || true; \
	  echo "---- Pods (wide) ----"; \
	  $(KUBECTL) -n "$$ns" get pods -l control-plane=controller-manager -o wide || true; \
	  echo "---- Pod describe (image pull and config errors surface here) ----"; \
	  $(KUBECTL) -n "$$ns" describe pods -l control-plane=controller-manager || true; \
	  echo "---- Events (recent 20) ----"; \
	  $(KUBECTL) -n "$$ns" get events --sort-by=.lastTimestamp | tail -n 20 || true; \
	  echo "---- Pod logs (last 50, empty if no container started) ----"; \
	  for p in $$( $(KUBECTL) -n "$$ns" get pods -l control-plane=controller-manager -o name 2>/dev/null ); do \
	    echo "-- $$p --"; \
	    $(KUBECTL) -n "$$ns" logs "$$p" --tail=50 2>/dev/null || true; \
	  done; \
	  echo ">>> End of debug info"; \
	  echo ">>> Performing clean restart (scale 0 -> 1)..."; \
	  $(KUBECTL) -n "$$ns" scale deploy/"$$dep" --replicas=0; \
	  for i in $$(seq 1 24); do \
	    cnt="$$( $(KUBECTL) -n "$$ns" get pods -l control-plane=controller-manager --no-headers 2>/dev/null | wc -l | tr -d " " )"; \
	    [ "$$cnt" = "0" ] && break; \
	    sleep 5; \
	  done; \
	  $(KUBECTL) -n "$$ns" scale deploy/"$$dep" --replicas=1; \
	  echo ">>> Retrying rollout (210s)..."; \
	  $(KUBECTL) -n "$$ns" rollout status deploy/"$$dep" --timeout=210s; \
	fi; \
	$(KUBECTL) -n "$$ns" wait --for=condition=Available deploy/"$$dep" --timeout=120s; \
	echo ">>> Deployment $$dep successfully rolled out and ready."; \
	'
endef

.PHONY: e2e-diagnostics
e2e-diagnostics: ## Dump cluster state into ./e2e-logs, which CI uploads as an artifact on failure.
	mkdir -p e2e-logs
	-$(KUBECTL) -n $(OPERATOR_NS) get pods -o wide > e2e-logs/operator-pods.txt 2>&1
	-$(KUBECTL) -n $(OPERATOR_NS) describe pods >> e2e-logs/operator-pods.txt 2>&1
	-$(KUBECTL) -n $(OPERATOR_NS) logs deploy/$(OPERATOR_NAME)-controller-manager --tail=6000 > e2e-logs/controller.log 2>&1
	-$(KUBECTL) -n $(OPERATOR_NS) logs deploy/$(OPERATOR_NAME)-controller-manager --previous --tail=3000 > e2e-logs/controller-previous.log 2>&1
	-$(KUBECTL) -n $(OPENBAO_NS) get pods -o wide > e2e-logs/openbao-pods.txt 2>&1
	-$(KUBECTL) get events -A --sort-by=.lastTimestamp > e2e-logs/events.txt 2>&1
	-$(KUBECTL) get openbaopolicies,openbaosecretengines,openbaonamespaces -A -o yaml > e2e-logs/openbao-crs.yaml 2>&1

.PHONY: deploy
deploy: kustomize setup-cluster openbao-install openbao-provision-creds openbao-bootstrap-auth install
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG) && \
	$(KUSTOMIZE) edit set configmap controller-manager-config --from-literal=VAULT_ADDR='$(VAULT_ADDR)' --namespace $(OPERATOR_NS)
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -
	$(KUBECTL) wait --for=condition=Established crd/openbaopolicies.security.mto.stakater.com --timeout=60s
	$(call rollout-controller-with-retry)

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: cluster
cluster: ## Setup Kind cluster with specified action (default: cluster). Usage: make cluster ACTION=<action>
	curl -sSL https://raw.githubusercontent.com/stakater/.github/refs/heads/main/.github/scripts/setup-kind-cluster.sh | \
	TEST_CLUSTER_NAME=$(TEST_CLUSTER_NAME) \
	IMG=$(IMG) \
	CONTAINER_TOOL=$(CONTAINER_TOOL) \
	KIND_VERSION=$(KIND_VERSION) \
	LOCALBIN=$(LOCALBIN) \
	OPERATOR_NAMESPACE=$(OPERATOR_NS) \
	PULL_SECRET_NAME=saap-dockerconfigjson \
	GHCR_USERNAME=$(GHCR_USERNAME) \
	GHCR_TOKEN=$(GHCR_TOKEN) \
	bash -s $(ACTION)

.PHONY: pull-secret
pull-secret: ## Create pull secret for private registry
	$(MAKE) cluster ACTION=pull-secret

.PHONY: setup-cluster
setup-cluster: ## Setup complete Kind cluster with image loading and pull secret
	$(MAKE) cluster ACTION=all

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
HELM ?= $(shell command -v helm || echo $(PWD)/bin/helm)
HELMIFY ?= $(LOCALBIN)/helmify
KIND ?= $(LOCALBIN)/kind

## Tool Versions
KUSTOMIZE_VERSION ?= v5.4.3
CONTROLLER_TOOLS_VERSION ?= v0.19.0
ENVTEST_VERSION ?= release-0.19
GOLANGCI_LINT_VERSION ?= v1.64.4
HELMIFY_VERSION ?= v0.4.20
KIND_VERSION ?= v0.30.0

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: helmify-bin
helmify-bin: $(HELMIFY) ## Install the helmify binary. The chart itself is built by the helmify target.
$(HELMIFY): $(LOCALBIN)
	$(call go-install-tool,$(HELMIFY),github.com/arttor/helmify/cmd/helmify,${HELMIFY_VERSION})

.PHONY: helm
helm: $(HELM)
$(HELM): $(LOCALBIN)
	@if [ ! -f $(HELM) ]; then \
		echo "Downloading helm v3.19.0" ;\
		curl -sSLO https://get.helm.sh/helm-v3.19.0-linux-amd64.tar.gz ;\
		tar -zxvf helm-v3.19.0-linux-amd64.tar.gz ;\
		mv linux-amd64/helm $(HELM) ;\
		rm -rf linux-amd64 helm-v3.19.0-linux-amd64.tar.gz ;\
		chmod +x $(HELM) ;\
	else \
		echo "Helm already installed at $(HELM)" ;\
	fi

.PHONY: kind
kind: $(KIND)
$(KIND): $(LOCALBIN)
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))

##@ Helm chart (operator)

# Operator chart — auto-generated via helmify from config/default kustomize
# output. Regenerated on every release; never committed.
HELM_CHART_NAME      ?= $(OPERATOR_NAME)
HELM_CHART_DIR       ?= charts/$(HELM_CHART_NAME)

HELM_REGISTRY        ?= $(DOCKER_REPO_BASE)/charts
CHART_VERSION        ?= $(VERSION)$(GIT_TAG)
HELMIFY_POSTPROCESS  ?=

# Shared helm release pipeline. Pulled from stakater/.github at first use.
HELM_MK_URL ?= https://raw.githubusercontent.com/stakater/.github/refs/heads/main/.github/makefiles/helm.mk
HELM_MK     := makefiles/helm.mk

.PHONY: download-helm-mk
download-helm-mk: ## Download shared helm.mk if missing.
	@if [ ! -f $(HELM_MK) ]; then \
		mkdir -p $(dir $(HELM_MK)); \
		echo "Downloading $(HELM_MK_URL) -> $(HELM_MK)"; \
		curl -fsSL $(HELM_MK_URL) -o $(HELM_MK); \
	fi

# helm.mk logs in to ghcr.io with GIT_USER/GIT_TOKEN; the CI chart-push action only
# exports GHCR_USERNAME/GHCR_TOKEN, so fall back to those when GIT_* is unset.
GIT_USER  ?= $(GHCR_USERNAME)
GIT_TOKEN ?= $(GHCR_TOKEN)

HELM_MK_CMD = GOBIN=$(LOCALBIN) PATH="$(LOCALBIN):$$PATH" $(MAKE) -f $(HELM_MK)
# helm.mk references $(KUSTOMIZE) but never defines it, so it has to be passed in.
HELM_MK_ARGS = \
	KUSTOMIZE=$(KUSTOMIZE) \
	GIT_USER=$(GIT_USER) \
	GIT_TOKEN=$(GIT_TOKEN) \
	OPERATOR_NAME=$(OPERATOR_NAME) \
	HELM_CHART_NAME=$(HELM_CHART_NAME) \
	HELM_CHART_DIR=$(HELM_CHART_DIR) \
	HELM_REGISTRY=$(HELM_REGISTRY) \
	CHART_VERSION=$(CHART_VERSION) \
	HELMIFY_POSTPROCESS=$(HELMIFY_POSTPROCESS) \
	IMG=$(IMG)

# helm.mk's helm-release runs lint, package and push in one target, so it cannot
# be stopped after generation. helmify below is the same pipeline's first step on
# its own, for inspecting or diffing the chart without publishing it. It needs no
# registry credentials: helm.mk gates only its push path on GIT_USER/GIT_TOKEN.
.PHONY: helmify
helmify: manifests helmify-bin kustomize yq download-helm-mk ## Generate the operator chart into $(HELM_CHART_DIR).
	@$(HELM_MK_CMD) helmify $(HELM_MK_ARGS)

.PHONY: helm-release
helm-release: helm-release-operator ## Release the operator chart to OCI.

.PHONY: helm-release-operator
helm-release-operator: manifests helmify-bin kustomize yq download-helm-mk ## Helmify config/default and release the operator chart.
	@$(HELM_MK_CMD) helm-release $(HELM_MK_ARGS)

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

.PHONY: operator-sdk
OPERATOR_SDK ?= $(LOCALBIN)/operator-sdk
operator-sdk: ## Download operator-sdk locally if necessary.
ifeq (,$(wildcard $(OPERATOR_SDK)))
ifeq (, $(shell which operator-sdk 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPERATOR_SDK)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPERATOR_SDK) https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$${OS}_$${ARCH} ;\
	chmod +x $(OPERATOR_SDK) ;\
	}
else
OPERATOR_SDK = $(shell which operator-sdk)
endif
endif

.PHONY: bundle
bundle: manifests kustomize operator-sdk ## Generate bundle manifests and metadata, then validate generated files.
	$(OPERATOR_SDK) generate kustomize manifests -q
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/manifests | $(OPERATOR_SDK) generate bundle $(BUNDLE_GEN_FLAGS)
	$(OPERATOR_SDK) bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)

.PHONY: opm
OPM = $(LOCALBIN)/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v1.23.0/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

.PHONY: yq
YQ_VERSION := v4.44.3
YQ_BIN := $(LOCALBIN)/yq
yq:
ifeq (,$(wildcard $(YQ_BIN)))
ifeq (,$(shell which yq 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(YQ_BIN)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(YQ_BIN) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$${OS}-$${ARCH} ;\
	chmod +x $(YQ_BIN) ;\
	}
else
YQ_BIN = $(shell which yq)
endif
endif

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)$(GIT_TAG)

# Set CATALOG_BASE_IMG to an existing catalog image tag to add $BUNDLE_IMGS to that image.
ifneq ($(origin CATALOG_BASE_IMG), undefined)
FROM_INDEX_OPT := --from-index $(CATALOG_BASE_IMG)
endif

# Render bundle to the catalog index.
.PHONY: catalog-render
catalog-render: opm yq ## Render bundle to catalog index.
	bash generate-catalog-index.sh $(DOCKER_REPO_BASE) $(OPERATOR_NAME) $(CATALOG_DIR_PATH) $(VERSION) $(GIT_TAG)

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm' in 'semver' bundle add mode. For more information on add modes, see:
# https://github.com/operator-framework/community-operators/blob/7f1438c/docs/packaging-operator.md#updating-your-existing-operator
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(OPM) index add --container-tool docker --mode semver --tag $(CATALOG_IMG) --bundles $(BUNDLE_IMGS) $(FROM_INDEX_OPT)

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)

# Push the catalog image.
.PHONY: publish
publish: ## Build and publish operator.
	echo $(BUNDLE_IMGS)
	$(MAKE) manifests build docker-build docker-push
	rm -f bin/kustomize
	$(MAKE) bundle bundle-build bundle-push
	$(MAKE) catalog-render catalog-build catalog-push
