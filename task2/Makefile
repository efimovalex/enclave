.PHONY: help docs
.DEFAULT_GOAL := help
.EXPORT_ALL_VARIABLES:

APP:=kyberAPI
BINARY_NAME:=kyberAPI
MINCOVERAGE?=70
PKG_LIST=$(shell go list ./... | grep -Ev "vendor|docs|cmd|mock")
GOCACHE=$(shell pwd)/.build
COVERAGE_DIR?=.coverage
LOG_LEVEL?=debug
LOG_PRETTY?=true
REST_PRETTY?=true


help: ## This help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

test-ci: # lint ## Runs the tests with coverage checks + lint
	@if [ -d ${COVERAGE_DIR} ]; then rm -rf ${COVERAGE_DIR}/*; else mkdir ${COVERAGE_DIR}; fi;
	@for package in ${PKG_LIST} ; do \
		pkgcov=$$(go test -covermode=atomic -test.count=1  -race -coverprofile="$(COVERAGE_DIR)/$$(basename $${package}).cov" "$${package}"); \
		retVal=$$? ;\
		if [ $$retVal -ne 0 ]; then \
			echo "$$pkgcov"; \
			echo " 🚨 TEST FAIL" ;\
			exit $$retVal; \
		fi;\
		pcoverage=$$(echo $$pkgcov| grep "coverage" | sed -E "s/.*coverage: ([0-9]*\.[0-9]+)\% of statements/\1/g") ;\
		if [ ! -z "$$pcoverage" ]; then \
			if [ $$(echo $${pcoverage%%.*}) -lt $(MINCOVERAGE) ] ; then \
				echo " 🚨 COVERAGE FAIL";\
				echo " 🚨 Test coverage of $$package is $$pcoverage%";\
				echo "FAIL" ;\
				echo ;\
				exit 1 ;\
			else \
				echo " ✅  Test coverage of $$package is $$pcoverage%" ;\
			fi \
		else \
			echo " ❗ No tests for $$package" ;\
		fi \
	done 
	@echo 'mode: atomic' > "$(COVERAGE_DIR)"/coverage.cov ;\
	for fcov in "$(COVERAGE_DIR)"/*.cov; do \
		if [ $$fcov != "$(COVERAGE_DIR)/coverage.cov" ]; then \
			tail -q -n +2 $$fcov >> $(COVERAGE_DIR)/coverage.cov ;\
		fi \
	done
	@echo 
	@pcoverage=$$(go tool cover -func=$(COVERAGE_DIR)/coverage.cov | grep 'total' | awk '{print substr($$3, 1, length($$3)-1)}');\
	echo "coverage: $$pcoverage% of project" ;\
	if [ $$(echo $${pcoverage%%.*}) -lt $$MINCOVERAGE ] ; then \
      echo ">> 🚨 Test coverage of project is $$pcoverage%" ;\
      echo "FAIL" ;\
      exit 1 ;\
	else \
		echo ">>  ✅  Test coverage of project is $$pcoverage%";\
	fi

test: ## Runs all tests normally
	go test -covermode=atomic -test.count=1 -race ./...

lint: ## Runs the linter
	golangci-lint run ./...

build: ## Builds go binary
	go build -o ./build/$(BINARY_NAME) ./cmd/main.go

run: docs ## Runs main package
	go run ./cmd/main.go

.PHONY: build run test lint test-ci