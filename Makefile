push:
	pip3 install wheel
	pip3 install --upgrade setuptools
	rm -rf ./dist ./build ./ydsdk.egg-info
	python3 setup.py sdist bdist_wheel
	python3 -m twine upload dist/*
install:
	python3 setup.py install
