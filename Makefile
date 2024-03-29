.PHONY: release test


lint-types:
	mypy guardpost --explicit-package-bases


artifacts: test
	python -m build


clean:
	rm -rf dist/


prepforbuild:
	pip install build


build:
	python -m build


test-release:
	twine upload --repository testpypi dist/*


release:
	twine upload --repository pypi dist/*


test:
	python -m pytest


test-cov:
	python -m pytest --cov-report html --cov=guardpost tests/


lint: check-flake8 check-isort check-black

format:
	@isort guardpost 2>&1
	@isort tests 2>&1
	@black guardpost 2>&1
	@black tests 2>&1

check-flake8:
	@echo "$(BOLD)Checking flake8$(RESET)"
	@flake8 guardpost 2>&1
	@flake8 tests 2>&1


check-isort:
	@echo "$(BOLD)Checking isort$(RESET)"
	@isort --check-only guardpost 2>&1
	@isort --check-only tests 2>&1


check-black:  ## Run the black tool in check mode only (won't modify files)
	@echo "$(BOLD)Checking black$(RESET)"
	@black --check guardpost 2>&1
	@black --check tests 2>&1
