# Contributing to Enchantrix

First off, thank you for considering contributing to Enchantrix! It's people like you that make open source such a great community.

## Where do I go from here?

If you've noticed a bug or have a feature request, [make one](https://github.com/Snider/Enchantrix/issues/new)! It's generally best if you get confirmation of your bug or approval for your feature request this way before starting to code.

### Fork & create a branch

If this is something you think you can fix, then [fork Enchantrix](https://github.com/Snider/Enchantrix/fork) and create a branch with a descriptive name.

A good branch name would be (where issue #38 is the ticket you're working on):

```sh
git checkout -b 38-add-awesome-new-feature
```

## Getting started

### Development Environment

To get started with development, you'll need to have Go 1.25 installed on your system, as specified in the `go.mod` file. You can download it from the official [Go website](https://go.dev/dl/).

Once you have Go installed, you can clone your fork of the repository:

```sh
git clone https://github.com/YOUR_USERNAME/Enchantrix.git
cd Enchantrix
```

### Running Tests

Enchantrix uses the standard Go testing tools. To run all tests, use the following command from the root of the repository:

```sh
go test ./...
```

To run tests with race detection, which is recommended:

```sh
go test -race ./...
```

To generate a coverage report:

```sh
go test -coverprofile=coverage.out ./...
```

## Code Style

This project follows standard Go coding conventions. Please ensure your code is formatted with `gofmt` before submitting a pull request. Most IDEs can be configured to do this automatically on save.

```sh
gofmt -w .
```

## Submitting a Pull Request

When you're ready to submit a pull request, please make sure you do the following:

1.  **Write tests.** Your patch won't be accepted if it doesn't have tests.
2.  **Follow the style guide.** Your code should be formatted with `gofmt`.
3.  **Write a good commit message.** A good commit message should be descriptive and concise.
4.  **Push to your fork** and submit a pull request.
5.  **Ensure the test suite passes.** The CI pipeline will run the tests, and your PR will not be merged if the tests are failing.

We'll review your pull request as soon as possible. We may suggest some changes or improvements or approve it as is.
