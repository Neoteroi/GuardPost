.PHONY: release test


lint-types:
	mypy neoteroi --explicit-package-bases


artifacts: test
	python setup.py sdist bdist_wheel


clean:
	rm -rf dist/


prepforbuild:
	pip install --upgrade twine setuptools wheel


uploadtest:
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*


release: clean artifacts
	twine upload --repository-url https://upload.pypi.org/legacy/ dist/*


test:
	python -m pytest


testcov:
	python -m pytest --cov-report html --cov=guardpost tests/


lint: check-flake8 check-isort check-black

format:
	@isort neoteroi 2>&1
	@isort tests 2>&1
	@black neoteroi 2>&1
	@black tests 2>&1

check-flake8:
	@echo "$(BOLD)Checking flake8$(RESET)"
	@flake8 neoteroi 2>&1
	@flake8 tests 2>&1


check-isort:
	@echo "$(BOLD)Checking isort$(RESET)"
	@isort --check-only neoteroi 2>&1
	@isort --check-only tests 2>&1


check-black:  ## Run the black tool in check mode only (won't modify files)
	@echo "$(BOLD)Checking black$(RESET)"
	@black --check neoteroi 2>&1
	@black --check tests 2>&1
