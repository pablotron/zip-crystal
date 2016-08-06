require "./spec_helper"

describe Zip do
  # TODO: Write tests

  it "works" do
    Zip::VERSION.should eq(Zip::VERSION)
  end
end

describe Zip::Writer do
  Zip.write("test.zip") do |zip|
    zip.add("foo.txt", MemoryIO.new("foo"))
  end
end
