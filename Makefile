.PHONY: demo test clean

demo:
	@python3 demo/privacy_receipt_demo.py

test:
	@python3 -m pytest tests/ -v

clean:
	@rm -rf __pycache__ src/__pycache__ tests/__pycache__ demo/__pycache__ src/connectors/__pycache__
