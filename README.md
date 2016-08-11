# zip-crystal

Read and write zip archives natively from
[Crystal](http://crystal-lang.org/).

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  zip-crystal:
    github: pablotron/zip-crystal
```

## Usage

```crystal
require "zip-crystal/zip"

# write to "foo.zip"
Zip.write("foo.zip") do |zip|
  # add "bar.txt" with contents "hello!"
  zip.add("bar.txt", "hello!")

  # add local file "/path/to/image.png" as "image.png"
  zip.add_file("image.png", "/path/to/image.png")
end

# create memory io
mem_io = MemoryIO.new

# read from "foo.zip"
Zip.read("foo.zip") do |zip|
  # extract "bar.txt" to mem_io
  zip["bar.txt"].write(mem_io)

  # extract "image.png" to "output-image.png"
  zip["image.png"].write("output-image.png")
end
```

See the [API documentation](https://pablotron.github.com/zip-crystal/)
for additional information.

## Contributing

1. Fork it ( https://github.com/pablotron/zip-crystal/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [pablotron](https://github.com/pablotron) Paul Duncan - creator, maintainer
