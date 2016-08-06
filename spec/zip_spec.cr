require "./spec_helper"

TEST_DIR = File.dirname(__FILE__)

describe Zip do
  # TODO: Write tests

  it "works" do
    Zip::VERSION.should eq(Zip::VERSION)
  end
end

describe Zip::Writer do
  Zip.write(File.join(TEST_DIR, "test.zip")) do |zip|
    zip.add("foo.txt", MemoryIO.new("foo"))
    zip.add("bar.txt", "bar")
    zip.add_file("shard.yml", File.join(TEST_DIR, "..", "shard.yml"))
  end
end
