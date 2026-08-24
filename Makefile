.PHONY: all test demo check learn ui clean

all: test demo

test:
	python -m unittest discover tests

demo:
	python -m prahari.cli demo boots/

learn:
	python -m prahari.cli learn boots/

check:
	python -m prahari.cli check boots/boot-0.log --viz boot.html

ui:
	python -m prahari.cli ui boots/

clean:
	rm -rf __pycache__ prahari/__pycache__ tests/__pycache__ .pytest_cache *.egg-info build dist
