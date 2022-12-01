# ssrfgen

ssrfgen is a small CLI responsible for retrieving and transforming the IP
prefixes listed in the IANA Special Purpose Registries for IPv4 and IPv6.

It works by:
* Retrieving the CSV with prefixes
* Transforming each network listed into a series of prefixes
* Reducing the prefixes by removing redundant entries
* Writing out a template for Go code and formatting it with `go fmt`

## Usage

```
Usage of ssrfgen:
  -output.gen string
    	file to write the generated code into

```
