require "./spec_helper"

TEST_DIR = File.dirname(__FILE__)
TEST_FILE_PATH = File.join(TEST_DIR, "..", "src", "zip.cr")

describe Zip do
  # TODO: Write tests

  it "works" do
    Zip::VERSION.should eq(Zip::VERSION)
  end
end

describe Zip::Writer do
  it "creates an empty archive" do
    Zip.write(File.join(TEST_DIR, "test-empty.zip")) do |zip|
      # do nothing
    end
  end

  it "creates an entry from a String" do
    Zip.write(File.join(TEST_DIR, "test-string.zip")) do |zip|
      zip.add("bar.txt", "bar")
    end
  end

  it "creates an entry from a String with no compression" do
    Zip.write(File.join(TEST_DIR, "test-string-none.zip")) do |zip|
      zip.add(
        path:   "bar.txt",
        data:   "bar",
        method: Zip::CompressionMethod::NONE
      )
    end
  end

  it "creates an entry from a MemoryIO" do
    Zip.write(File.join(TEST_DIR, "test-memio.zip")) do |zip|
      zip.add("bar.txt", "bar")
    end
  end

  it "creates an entry from a File" do
    Zip.write(File.join(TEST_DIR, "test-file.zip")) do |zip|
      zip.add_file("test.cr", TEST_FILE_PATH)
    end
  end

  it "creates an archive from a MemoryIO, String, and File" do
    Zip.write(File.join(TEST_DIR, "test-many.zip")) do |zip|
      zip.add("foo.txt", MemoryIO.new("foo"))
      zip.add("bar.txt", "bar")
      zip.add_file("test.cr", TEST_FILE_PATH)
    end
  end
end

describe Zip::Reader do
  it "reads an archive" do
    Zip.read(File.join(TEST_DIR, "test-string.zip")) do |zip|
      zip.entries.each do |e|
        pp e.path
      end
    end
  end

  it "reads an archive created by an external program" do
    Zip.read(File.join(TEST_DIR, "real.zip")) do |zip|
      zip.each do |e|
        pp e.path
      end
    end
  end

  it "reads an archive created by an external program" do
    Zip.read(File.join(TEST_DIR, "real.zip")) do |zip|
      zip.each do |e|
        e.read(File.open("/dev/null", "wb"))
      end
    end
  end

  it "reads all an archive's compressed entries" do
    Zip.read(File.join(TEST_DIR, "test-many.zip")) do |zip|
      zip.each do |e|
        pp e.path

        io = MemoryIO.new
        # e.read(STDOUT)
        e.read(io)
        io.close
      end
    end
  end
end
