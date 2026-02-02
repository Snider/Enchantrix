# Frequently Asked Questions (FAQ)

This page answers some of the most common questions about Enchantrix.

## General

### What is the purpose of the .trix container format?

The .trix format is a generic binary container designed to hold a payload and associated metadata. It is protocol-agnostic, meaning it can be used to store any type of data. Its primary purpose is to provide a flexible and extensible format for data that may need to be transformed or encrypted.

### What are Sigils?

Sigils are the core concept of the Enchantrix transformation framework. Each Sigil represents a single, reversible data transformation, such as encoding, compression, or hashing. They can be chained together to create powerful and flexible transformation pipelines.

## Development

### How do I add a new Sigil?

To add a new Sigil, you need to create a new struct that implements the `enchantrix.Sigil` interface. This involves implementing the `In()` and `Out()` methods. Once your Sigil is implemented, you can add it to the `enchantrix.NewSigil()` factory function.

### Can I use my own magic number for the .trix format?

Yes, the `trix.Encode()` and `trix.Decode()` functions accept a custom 4-byte magic number string. This allows you to create your own application-specific file formats based on the .trix container.
