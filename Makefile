.PHONY: install build test fmt lint coverage clean

# Install dependencies and tools
install:
	forge install
	cargo install scopelint

# Build contracts
build:
	forge build

# Run tests
test:
	forge test

# Format code
fmt:
	scopelint fmt

# Check linting (formatting + validation)
lint:
	scopelint check

# Run coverage
coverage:
	forge coverage --report summary --report lcov

# Clean build artifacts
clean:
	forge clean
