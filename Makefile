SERVICE     := eightton-policy
REGISTRY    := v2-zcr.cloudzcp.io/cloudzcp
VERSION     ?= $(shell cat VERSION)
IMAGE       := $(REGISTRY)/$(SERVICE):$(VERSION)
NAMESPACE   := aiops-app
BUILDER_POD := eightton-builder

.PHONY: build push deploy restart all

build:
	@echo "=== Building $(IMAGE) ==="
	tar czf /tmp/$(SERVICE)-context.tar.gz \
		--exclude='.venv' --exclude='__pycache__' \
		--exclude='.git' --exclude='*.pyc' \
		-C . .
	kubectl cp /tmp/$(SERVICE)-context.tar.gz \
		$(NAMESPACE)/$(BUILDER_POD):/workspace/context.tar.gz
	kubectl exec -n $(NAMESPACE) $(BUILDER_POD) -- sh -c '\
		mkdir -p /workspace/build && \
		cd /workspace/build && \
		tar xzf /workspace/context.tar.gz && \
		/kaniko/executor \
			--context=/workspace/build \
			--dockerfile=/workspace/build/Dockerfile \
			--destination=$(IMAGE) \
			--cache=true && \
		rm -rf /workspace/build /workspace/context.tar.gz'
	rm -f /tmp/$(SERVICE)-context.tar.gz

deploy:
	kubectl apply -f k8s/ -n $(NAMESPACE)

restart:
	kubectl rollout restart deployment/$(SERVICE) -n $(NAMESPACE)

all: build deploy restart
