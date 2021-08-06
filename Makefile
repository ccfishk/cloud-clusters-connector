.PHONY: install uninstall lint macsetup

install:
	@./setup.py install

develop:
	@./setup.py develop

uninstall:
	@./setup.py install --record files.txt && cat files.txt | xargs rm -rf && rm files.txt

lint:
	@python3 -m flake8 --config=./.flake8 .

macsetup:
	@brew install pkg-config freetype libpng kops eksctl

macupgrade:
	@brew upgrade pkg-config freetype libpng kops eksctl
