.PHONY: docs
init:
	pip install pipenv --upgrade
	pipenv install --dev


py3.7-tests:
	tox -re py37,pep8,integrations
	coverage xml -i
	coverage html -i

py3.8-tests:
	tox -re py38,pep8,integrations
	coverage xml -i
	coverage html -i

py3.9-tests:
	tox -re py39,pep8,integrations
	coverage xml -i
	coverage html -i

integration-tests:
	tox -re integrations


publish-test:
	pip install 'twine>=1.5.0'
	python setup.py sdist bdist_wheel
	twine upload --repository testpypi dist/*
	rm -fr build dist .egg requests.egg-info

publish:
	pip install 'twine>=1.5.0'
	python setup.py sdist bdist_wheel
	twine upload dist/* --verbose
	rm -fr build dist .egg requests.egg-info

docs:
	sphinx-apidoc -o  docs/source/ ownca/
	cd docs && make clean && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
