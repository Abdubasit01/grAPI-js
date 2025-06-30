.PHONY: build test upload clean

build:
	python3 -m build

test:
	pytest tests/

upload: build
	twine upload dist/*

upload-test: build
	twine upload --repository testpypi dist/*

clean:
	rm -rf dist/ build/ *.egg-info
