require "./spec_helper"

TEST_DIR = File.dirname(__FILE__)
TEST_FILE_PATH = File.join(TEST_DIR, "..", "src", "zip.cr")

describe Zip do
  # TODO: Write tests

  it "works" do
    Zip::VERSION.should eq(Zip::VERSION)
  end

  ###############
  # write tests #
  ###############

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
      zip.add_dir("example-dir")
    end
  end

  ##############
  # read tests #
  ##############

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
        e.write("/dev/null")

        # p e.extras.map { |e| { e.code, e.size } }
        # p e.local_extras.map { |e| { e.code, e.size } }
      end
    end
  end

  it "reads all an archive's compressed entries" do
    Zip.read(File.join(TEST_DIR, "test-many.zip")) do |zip|
      puts "file has #{zip.size} entries"

      zip.each do |e|
        if e.dir?
          puts "#{e.path} is a directory"
        else
          io = MemoryIO.new
          # e.write(STDOUT)
          e.write(io)
          io.close
        end
      end
    end
  end

  it "reads jnl.zip" do
    Zip.read(File.join(TEST_DIR, "jnl.zip")) do |zip|
      puts "file has #{zip.size} entries"

      zip.each do |e|
        if e.dir?
          puts "#{e.path} is a directory"
        else
          puts "#{e.path} is a file"
        end
      end
    end
  end
end
