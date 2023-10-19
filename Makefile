
help:
	@echo 'Zappa Make Targets'
	@echo '-----------------------'
	@echo 'These targets are aimed at making development, testing, and building easier'
	@echo ''
	@echo 'Setup'
	@echo 'make clean: Remove the built files, local caches, mypy and coverage information'
	@echo 'make requirements: Generate requirements from requirements.in and install them to the current environment'
	@echo 'make build: Build the source and wheel'
	@echo ''
	@echo 'Linting'
	@echo 'make flake: Flake8 checking'
	@echo 'make mypy: Run static type checking for zappa and tests directories'
	@echo 'make isort: Sort imports'
	@echo 'make black: Format project code according to Black convention'
	@echo ''
	@echo 'Testing'
	@echo 'make tests: Run all project tests. Additional make targets exist for subsets of the tests. Inspect the Makefile for details'

.PHONY: clean requirements build flake mypy isort black tests

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	rm -rf .mypy_cache dist build *.egg-info
	coverage erase

requirements:
	pip install pip --upgrade
	pip install "pipenv>2021.11.15"

	pipenv lock
	pipenv sync --dev

build: clean requirements
	python setup.py sdist
	python setup.py bdist_wheel 

mypy:
	mypy --show-error-codes --pretty --ignore-missing-imports --strict zappa tests

black:
	black --line-length 127 .

black-check:
	black --line-length 127 . --check
	@echo "If this fails, simply run: make black"

isort:
	isort . --profile=black

isort-check:
	isort --check . --profile=black

flake:
	flake8 zappa --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 zappa --count --exit-zero --max-complexity=55 --max-line-length=127 --statistics --ignore F403,F405,E203,E231,E252,W503

test-docs:
	pytest tests/tests_docs.py --cov=zappa --durations=0

test-handler:
	pytest tests/test_handler.py --cov=zappa --durations=0

test-middleware:
	pytest tests/tests_middleware.py --cov=zappa --durations=0

test-placebo:
	pytest tests/tests_placebo.py --cov=zappa --durations=0

test-async:
	pytest tests/tests_async.py --cov=zappa --durations=0

test-general:
	pytest tests/tests.py --cov=zappa --durations=0

test-utilities:
	pytest tests/tests_utilities.py --cov=zappa --durations=0

coverage-report:
	coverage report --include="*/zappa*"

tests:
	make clean
	pytest \
		tests/tests_docs.py \
		tests/test_handler.py \
		tests/tests_middleware.py \
		tests/tests_placebo.py \
		tests/tests_async.py \
		tests/tests.py \
		tests/tests_utilities.py \
		--cov=zappa
		--durations=0

