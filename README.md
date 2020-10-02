# Restless Django Utils


## Build and push package

1. Update version in `restless_dj_utils/__init__.py`
2. Run `tox` to validate the tests pass
3. Run `python3 setup.py sdist bdist_wheel` to build the package
4. Run `python3 -m twine upload dist/*` to push to Pypi