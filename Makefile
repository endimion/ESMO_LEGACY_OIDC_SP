NAME = djart/esmocloak
VERSION = 0.0.43

.PHONY: all build

all: build

build:
	mvn clean install && docker build -t $(NAME):$(VERSION) --rm .
