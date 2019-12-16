push:
	rm -rf ./dist ./build ./ydsdk.egg-info
	pipenv run python setup.py sdist bdist_wheel
	pipenv run python -m twine upload dist/*
install:
	pipenv run python setup.py install
