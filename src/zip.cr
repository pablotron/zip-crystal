# require "./zip/*"
require "zlib"

# :nodoc:
#
# TODO:
# [x] date/time
# [x] reader (store and deflate only)
# [x] documentation
# [-] extras (at least infozip)
# [x] convert datetime to Time
# [x] add size to Entry
# [x] Version
# [x] directories
# [-] full tests
# [-] zip64
#   [x] add zip64 parameter
#   [x] add zip64 extras when writing header and central
#   [x] add zip64 archive footer
#   [x] update sizes to be u64
#   [x] reader support
#   [ ] choose zip64 default for arbitrary IOs (right now it is false)
#   [ ] testing
# [ ] legacy unicode (e.g., non-bit 11) path/comment support
# [ ] unix uids
# [ ] encryption
# [ ] bzip2/lzma support
#
# References:
#   https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
#   http://www.onicos.com/staff/iz/formats/zip.html
#
# :nodoc:

#
# Library for reading and writing zip files.
#
# Features:
# * Read and write zip files
# * Native Crystal, no dependencies other than zlib
# * Stream writing (e.g. write zip to socket, pipe or other arbitrary,
#   non-seekable IO)
# * ZIP64 support
# * Store and DEFLATE compression
# * UTF-8 filename and comment support (EFS)
#
# TODO:
# * LZMA and BZip2 compression
# * Encryption (Legacy and Strong Encryption)
# * Split archives (e.g. multi-disk archives)
# * Legacy Unicode support
#
# Examples:
#
# Reading from a zip file:
#
#     require "zip-crystal/zip"
#
#     # create output IO::Memory
#     mem_io = IO::Memory.new
#
#     # read from "foo.zip"
#     Zip.read("foo.zip") do |zip|
#       # read contents of "bar.txt" in "foo.zip" into mem_io
#       zip["bar.txt"].write(mem_io)
#     end
#
# Writing to a zip file:
#
#     # write to "foo.zip"
#     Zip.write("foo.zip") do |zip|
#       # create "bar.txt" with contents "hello!"
#       zip.add("bar.txt", "hello!")
#     end
#
module Zip
  #
  # Version of zip-crystal library.
  #
  VERSION = "0.1.2"

  #
  # Magic numbers for various data in Zip stream.
  #
  MAGIC = {
    cdr_header:   0x02014b50_u32,
    cdr_footer:   0x06054b50_u32,
    file_header:  0x04034b50_u32,
    file_footer:  0x08074b50_u32,
    z64_footer:   0x06064b50_u32,
    z64_locator:  0x07064b50_u32,
  }

  # :nodoc:
  LE = IO::ByteFormat::LittleEndian

  # :nodoc:
  # Static, zero-length `Bytes` used when empty buffer reference is
  # needed.
  # :nodoc:
  EMPTY_SLICE = Bytes.new(0)

  #
  # Size of internal buffers, in bytes.
  #
  BUFFER_SIZE = 8192

  # :nodoc:
  # 4.4.4 general purpose bit flag: (2 bytes)
  #
  # Bit 0: If set, indicates that the file is encrypted.
  #
  # (For Method 6 - Imploding)
  # Bit 1: If the compression method used was type 6,
  #        Imploding, then this bit, if set, indicates
  #        an 8K sliding dictionary was used.  If clear,
  #        then a 4K sliding dictionary was used.
  #
  # Bit 2: If the compression method used was type 6,
  #        Imploding, then this bit, if set, indicates
  #        3 Shannon-Fano trees were used to encode the
  #        sliding dictionary output.  If clear, then 2
  #        Shannon-Fano trees were used.
  #
  # (For Methods 8 and 9 - Deflating)
  # Bit 2  Bit 1
  #   0      0    Normal (-en) compression option was used.
  #   0      1    Maximum (-exx/-ex) compression option was used.
  #   1      0    Fast (-ef) compression option was used.
  #   1      1    Super Fast (-es) compression option was used.
  #
  # (For Method 14 - LZMA)
  # Bit 1: If the compression method used was type 14,
  #        LZMA, then this bit, if set, indicates
  #        an end-of-stream (EOS) marker is used to
  #        mark the end of the compressed data stream.
  #        If clear, then an EOS marker is not present
  #        and the compressed data size must be known
  #        to extract.
  #
  # Note:  Bits 1 and 2 are undefined if the compression
  #        method is any other.
  #
  # Bit 3: If this bit is set, the fields crc-32, compressed
  #        size and uncompressed size are set to zero in the
  #        local header.  The correct values are put in the
  #        data descriptor immediately following the compressed
  #        data.  (Note: PKZIP version 2.04g for DOS only
  #        recognizes this bit for method 8 compression, newer
  #        versions of PKZIP recognize this bit for any
  #        compression method.)
  #
  # Bit 4: Reserved for use with method 8, for enhanced
  #        deflating.
  #
  # Bit 5: If this bit is set, this indicates that the file is
  #        compressed patched data.  (Note: Requires PKZIP
  #        version 2.70 or greater)
  #
  # Bit 6: Strong encryption.  If this bit is set, you MUST
  #        set the version needed to extract value to at least
  #        50 and you MUST also set bit 0.  If AES encryption
  #        is used, the version needed to extract value MUST
  #        be at least 51. See the section describing the Strong
  #        Encryption Specification for details.  Refer to the
  #        section in this document entitled "Incorporating PKWARE
  #        Proprietary Technology into Your Product" for more
  #        information.
  #
  # Bit 7: Currently unused.
  #
  # Bit 8: Currently unused.
  #
  # Bit 9: Currently unused.
  #
  # Bit 10: Currently unused.
  #
  # Bit 11: Language encoding flag (EFS).  If this bit is set,
  #         the filename and comment fields for this file
  #         MUST be encoded using UTF-8. (see APPENDIX D)
  #
  # Bit 12: Reserved by PKWARE for enhanced compression.
  #
  # Bit 13: Set when encrypting the Central Directory to indicate
  #         selected data values in the Local Header are masked to
  #         hide their actual values.  See the section describing
  #         the Strong Encryption Specification for details.  Refer
  #         to the section in this document entitled "Incorporating
  #         PKWARE Proprietary Technology into Your Product" for
  #         more information.
  #
  # Bit 14: Reserved by PKWARE.
  #
  # Bit 15: Reserved by PKWARE.
  # :nodoc:

  #
  # General flags.
  #
  # Used by local header and central directory header.
  #
  @[Flags]
  enum GeneralFlags
    # encrypted using weak encryption
    ENCRYPTION

    # compression method-specific flag
    COMPRESSION_OPTION_1

    # compression method-specific flag
    COMPRESSION_OPTION_2

    # this entry has a data descriptor footer
    FOOTER

    # reserved flag
    RESERVED_4

    # this entry is patch data
    PATCH

    # this entry uses strong encryption
    STRONG_ENCRYPTION

    # reserved flag
    RESERVED_7

    # reserved flag
    RESERVED_8

    # reserved flag
    RESERVED_9

    # reserved flag
    RESERVED_10

    # the file name and comment for this entry are UTF-8 encoded.
    EFS

    # reserved flag
    RESERVED_12

    # Some fields in the local header are masked (that is, empty).
    MASKED_VALUES

    # reserved flag
    RESERVED_14

    # reserved flag
    RESERVED_15
  end

  #
  # Compression methods.
  #
  enum CompressionMethod
    # Stored (no compression)
    NONE = 0

    # Shrunk
    SHRUNK = 1

    # Reduced with compression factor 1
    REDUCED_1 = 2

    # Reduced with compression factor 2
    REDUCED_2 = 3

    # Reduced with compression factor 3
    REDUCED_3 = 4

    # Reduced with compression factor 4
    REDUCED_4 = 5

    # Imploded
    IMPLODED = 6

    # Reserved for Tokenizing compression algorithm
    TOKENIZED = 7

    # Deflated
    DEFLATE = 8

    # Enhanced Deflating using Deflate64(tm)
    DEFLATE64 = 9

    # PKWARE Data Compression Library Imploding (old IBM TERSE)
    TERSE_OLD = 10

    # Reserved by PKWARE
    RESERVED_11 = 11

    # BZIP2
    BZIP2 = 12

    # Reserved by PKWARE
    RESERVED_13 = 13

    # LZMA (EFS)
    LZMA = 14

    # Reserved by PKWARE
    RESERVED_15 = 15

    # Reserved by PKWARE
    RESERVED_16 = 16

    # Reserved by PKWARE
    RESERVED_17 = 17

    # IBM TERSE (new)
    TERSE = 18

    # IBM LZ77 z Architecture (PFS)
    LZ77 = 19

    # WavPack compressed data
    WAVPACK = 97

    # PPMd version I, Rev 1
    PPMD = 98
  end

  #
  # Wrapper class for exceptions.
  #
  # You shouldn't need to instantiate this class directly; it is raised
  # by other classes on error.
  #
  class Error < Exception
  end

  #
  # Version identifier used to identify the version needed to extract a
  # given file and to indicate the format of the external file
  # attributes.
  #
  # See section 4.4.3.2 of APPNOTE.TXT for version details.
  #
  # Example:
  #
  #     # create version and print it out
  #     version = Zip::Version.new(5, 0)
  #     puts "version = #{version}"
  #
  class Version
    #
    # Version needed to extract this entry (4.4.3.2).
    #
    NEEDED = new(2, 0)

    #
    # Version needed to extract Zip64 entries.
    #
    ZIP64 = new(4, 6)

    #
    # Default version made by, if unspecified.
    #
    DEFAULT = new(0, 0)

    #
    # Create a version identifier from a major number, minor number, and
    # optional compatability number.
    #
    # Example:
    #
    #     # create version and print it out
    #     version = Zip::Version.new(5, 0)
    #     puts "version = #{version}"
    #
    def initialize(
      @major  : Int32,
      @minor  : Int32,
      @compat : Int32 = 0
    )
    end

    #
    # Create a version identifier from a major number, minor number, and
    # optional compatability number.
    #
    # You shouldn't need to call this constructor directly; it is used
    # by internal classes.
    #
    def initialize(v : UInt16)
      @compat = v.to_i >> 8
      @major = (v.to_i & 0xff) / 10
      @minor = (v.to_i & 0xff) % 10
    end

    #
    # Write version as string.
    #
    #     # create version and print it out
    #     version = Zip::Version.new(5, 0)
    #     puts "version = #{version}"
    #
    def to_s(io)
      io << @major << "." << @minor
    end

    #
    # Write version as 16-bit, little-endian integer and return number
    # of bytes written.
    #
    # You shouldn't need to call this method directly; it is used by
    # internal classes.
    #
    def to_io(io)
      (
        ((@compat & 0xff) << 8) +
        ((@major * 10) + (@minor % 10)) & 0xff
      ).to_u16.to_io(io, LE)
    end
  end

  #
  # Extra data handlers.
  #
  module Extra
    #
    # Raw extra data associated with `Entry`.
    #
    # You should not need to instantiate this class directly; use
    # `Zip::Entry#extras` or `Zip::Entry#local_extras` instead.
    #
    # Example:
    #
    #     # open "foo.zip"
    #     Zip.read("foo.zip") do |zip|
    #       # get extra data associated with "bar.txt"
    #       extras = zip["bar.txt"].extras
    #     end
    #
    class Base
      #
      # Identifier for this extra entry.
      #
      property :code

      #
      # Data for this extra entry.
      #
      property :data

      #
      # Create a new raw extra data entry.
      #
      # You should not need to instantiate this class directly; it is
      # created as-needed by `Writer#add`.
      #
      def initialize(@code : UInt16, @data : Bytes)
      end

      #
      # Return number of bytes needed for this Extra.
      #
      def bytes_needed : UInt16
        (4 + @data.size).to_u16
      end

      def to_s(io) : UInt16
        @code.to_u16.to_io(io, LE)
        @data.size.to_u16.to_io(io, LE)
        @data.to_s(io) if @data.size > 0

        # return number of bytes written
        bytes_needed
      end
    end

    #
    # ZIP64 extra data associated with `Entry`.
    #
    # You should not need to instantiate this class directly; it is
    # created as-needed by `Writer#add()`.
    #
    class Zip64 < Base
      #
      # File size (64-bit unsigned integer).
      #
      getter :size

      #
      # Compressed file size (64-bit unsigned integer).
      #
      getter :compressed_size

      #
      # Position in output (optional).
      #
      getter :pos

      #
      # Starting disk (optional).
      #
      getter :disk_start

      #
      # ZIP64 extra code
      #
      CODE = 0x0001.to_u16

      #
      # Create ZIP64 extra data associated with `Entry` from given
      # attributes.
      #
      # You should not need to instantiate this class directly; it is
      # created as-needed by `Writer#add()`.
      #
      def initialize(
        @size             : UInt64 = 0_u64,
        @compressed_size  : UInt64 = 0_u64,
        @pos              : UInt64? = nil,
        @disk_start       : UInt32? = nil,
      )
        len = 16_u32
        len += 8 if @pos
        len += 4 if @disk_start

        # create backing buffer and mem io
        buf = Bytes.new(len)
        io = IO::Memory.new(buf)

        @size.to_u64.to_io(io, LE)
        @compressed_size.to_u64.to_io(io, LE)
        @pos.not_nil!.to_u64.to_io(io, LE) if @pos
        @disk_start.not_nil!.to_u32.to_io(io, LE) if @disk_start

        # close io
        io.close

        super(CODE, buf)
      end

      #
      # Parse ZIP64 extra data from given buffer.
      #
      # You should not need to instantiate this class directly; it is
      # created as-needed by `Archive`.
      #
      def initialize(data : Bytes)
        super(CODE, data)

        # create memory io over buffer
        io = IO::Memory.new(data, false)

        @size = UInt64.from_io(io, LE).as(UInt64)
        @compressed_size = UInt64.from_io(io, LE).as(UInt64)

        @pos, @disk_start = case data.size - 16
        when 12
          { UInt64.from_io(io, LE), UInt32.from_io(io, LE) }
        when 8
          { UInt64.from_io(io, LE), nil }
        when 4
          { nil, UInt32.from_io(io, LE) }
        when 0
          { nil, nil }
        else
          raise Error.new("invalid Zip64 extra data: #{data.size}")
        end
      end
    end

    #
    # Parse `Extra` data from given IO *io*.
    #
    def self.read(io) : Base
      # read code and length
      code = UInt16.from_io(io, LE).as(UInt16)
      len = UInt16.from_io(io, LE).as(UInt16)

      # read buffer
      data = Bytes.new(len)
      io.read_fully(data)

      case code
      when Zip64::CODE
        Zip64.new(data)
      else
        Base.new(code, data)
      end
    end

    #
    # Encode array of `Extra::Base` and return buffer.
    #
    def self.pack(extras : Array(Extra::Base)?) : Bytes
      if extras && extras.size > 0
        # create backing buffer for extras
        buf = Bytes.new(extras.reduce(0) { |r, e| r + e.bytes_needed })

        # create io and write each extra data to io
        io = IO::Memory.new(buf)
        extras.each { |e| e.to_s(io) }
        io.close

        # return buffer
        buf
      else
        # return empty slice
        EMPTY_SLICE
      end
    end
  end

  #
  # Helper methods for converting to and from `Time` objects.
  #
  module TimeHelper
    #
    # Convert given `Time` to a DOS-style datetime, write the result to
    # the given IO, and return the number of bytes written.
    #
    private def write_time(io : IO, time : Time) : UInt32
      year = Math.max(1980, time.year) - 1980

      # convert to dos timestamp
      ((
        (year << 25) | (time.month << 21) | (time.day << 16) |
        (time.hour << 11) | (time.minute << 5) | (time.second >> 1)
      ) & UInt32::MAX).to_u32.to_io(io, LE)

      # return number of bytes written
      4_u32
    end

    #
    # Convert given DOS datetime to a `Time` object.
    #
    private def from_dos_time(v : UInt32) : Time
      Time.new(
        year:   (v >> 25) + 1980,
        month:  (v >> 21) & 0b0000_1111,
        day:    (v >> 16) & 0b0001_1111,
        hour:   (v >> 11) & 0b0001_1111,
        minute: (v >> 5)  & 0b0011_1111,
        second: (v << 1)  & 0b0011_1110,
      )
    end
  end

  #
  # Helper methods for reading and writing uncompressed data.
  #
  module NoneCompressionHelper
    private def compress_none(src_io, dst_io)
      crc = 0_u32

      buf = Bytes.new(BUFFER_SIZE)
      src_len = 0_u64

      while ((len = src_io.read(buf)) > 0)
        # build output slice
        dst_buf = (len < buf.size) ? buf[0, len] : buf
        dst_crc = Zlib.crc32(dst_buf)

        # update crc
        crc = if crc != 0
          Zlib.crc32_combine(crc, dst_crc, dst_buf.size)
        else
          Zlib.crc32(dst_buf)
        end


        # write to output buffer
        dst_io.write(dst_buf)
        src_len += len
      end

      # return results
      { crc.to_u32, src_len, src_len }
    end

    private def decompress_none(src_io, dst_io, src_len, dst_len)
      # TODO: verify CRC
      IO.copy(src_io, dst_io, src_len)

      # return number of bytes read
      dst_len
    end
  end

  #
  # Helper methods for compressing and decompressing deflated data.
  #
  module DeflateCompressionHelper
    ZALLOC_PROC = LibZ::AllocFunc.new do |data, num_items, size|
      GC.malloc(num_items * size)
    end

    ZFREE_PROC = LibZ::FreeFunc.new do |data, addr|
      GC.free(addr)
    end

    ZLIB_VERSION = LibZ.zlibVersion

    #
    # Read data from src_io, and write the compressed result to dst_io.
    #
    private def compress_deflate(src_io, dst_io)
      crc = 0_u32
      src_len = 0_u64
      dst_len = 0_u64

      # create read and compress buffers
      src_buf = Bytes.new(BUFFER_SIZE)
      dst_buf = Bytes.new(BUFFER_SIZE)

      # create deflate stream
      z = LibZ::ZStream.new(
        zalloc: ZALLOC_PROC,
        zfree:  ZFREE_PROC,
      )

      # init stream
      err = LibZ.deflateInit2(
        pointerof(z),
        LibZ::DEFAULT_COMPRESSION, # FIXME: make this configurable
        LibZ::Z_DEFLATED,
        -15, # raw deflate, window bits = 15
        LibZ::DEF_MEM_LEVEL,
        LibZ::Strategy::DEFAULT_STRATEGY,
        ZLIB_VERSION,
        sizeof(LibZ::ZStream)
      )

      # check for error
      if err != LibZ::Error::OK
        # raise zlib error
        raise Zlib::Error.new(err, z)
      end

      # loop and compress input data
      while ((len = src_io.read(src_buf)) > 0)
        # add to output counter
        src_len += len

        # build temp slice (if necessary)
        tmp_buf = (len < src_buf.size) ? src_buf[0, len] : src_buf
        tmp_crc = Zlib.crc32(tmp_buf)

        # update crc
        crc = if crc != 0
          Zlib.crc32_combine(crc, tmp_crc, tmp_buf.size)
        else
          Zlib.crc32(tmp_buf)
        end

        # set zlib input buffer
        z.next_in = tmp_buf.to_unsafe
        z.avail_in = tmp_buf.size.to_u32

        # write compressed data to dst io
        dst_len += write_compressed(dst_io, dst_buf, pointerof(z), false)
      end

      # set zlib input buffer to null
      z.next_in = Pointer(UInt8).null
      z.avail_in = 0_u32

      # flush remaining data
      dst_len += write_compressed(dst_io, dst_buf, pointerof(z), true)

      # free stream
      LibZ.deflateEnd(pointerof(z))

      # return results
      { crc.to_u32, src_len, dst_len }
    end

    #
    # Deflate data in ZStream and write it to given IO.
    #
    private def write_compressed(
      io    : IO,
      buf   : Bytes,
      zp    : Pointer(LibZ::ZStream),
      flush : Bool,
    ) : UInt32
      zf = flush ? LibZ::Flush::FINISH : LibZ::Flush::NO_FLUSH
      r = 0_u32

      loop do
        # set zlib output buffer
        zp.value.next_out = buf.to_unsafe
        zp.value.avail_out = buf.size.to_u32

        # compress data (TODO: check for error)
        LibZ.deflate(zp, zf)

        if ((len = buf.size - zp.value.avail_out) > 0)
          # write compressed buffer to dst io
          io.write((len < buf.size) ? buf[0, len] : buf)
          r += len
        end

        # exit loop if there is no remaining space
        break if zp.value.avail_out != 0
      end

      # return number of bytes written
      r
    end

    #
    # Decompress src_len bytes of DEFLATEd data from src_io and write it
    # to dst_io.
    #
    private def decompress_deflate(src_io, dst_io, src_len, dst_len)
      crc = 0_u32

      # create read and compress buffers
      src_buf = Bytes.new(BUFFER_SIZE)
      dst_buf = Bytes.new(BUFFER_SIZE)

      # create deflate stream
      z = LibZ::ZStream.new(
        zalloc: ZALLOC_PROC,
        zfree:  ZFREE_PROC,
      )

      # init stream
      err = LibZ.inflateInit2(
        pointerof(z),
        -15, # raw deflate, window bits = 15
        ZLIB_VERSION,
        sizeof(LibZ::ZStream)
      )

      # check for error
      if err != LibZ::Error::OK
        # raise zlib error
        raise Zlib::Error.new(err, z)
      end

      src_ofs, left = 0_u32, src_len
      while left > 0
        # calculate read buffer size
        tmp_len = Math.min(BUFFER_SIZE - src_ofs, left)

        # decriment remaining bytes
        left -= tmp_len

        # create read buffer (if necessary)
        tmp_buf = (tmp_len < BUFFER_SIZE) ? src_buf[src_ofs, tmp_len] : src_buf

        # read from source into buffer
        if ((len = src_io.read_fully(tmp_buf)) != tmp_len)
          raise Error.new("truncated read (got #{len}, expected #{tmp_len})")
        end

        # calculate crc
        tmp_crc = Zlib.crc32(tmp_buf)

        # update crc
        crc = if crc != 0
          Zlib.crc32_combine(crc, tmp_crc, tmp_buf.size)
        else
          tmp_crc
        end

        # set zlib input buffer
        z.next_in = src_buf.to_unsafe
        z.avail_in = src_ofs + tmp_buf.size.to_u32

        # read compressed data to dst io
        read_compressed(dst_io, dst_buf, pointerof(z), false)
      end

      # set zlib input buffer to null
      z.next_in = Pointer(UInt8).null
      z.avail_in = 0_u32

      # flush remaining data
      read_compressed(dst_io, dst_buf, pointerof(z), true)

      # free stream
      LibZ.inflateEnd(pointerof(z))

      # check crc
      if false && crc != @crc
        raise Error.new("crc mismatch (got #{crc}, expected #{@crc}")
      end

      # check input size
      if z.total_in != src_len
        raise Error.new("read length mismatch (got #{z.total_in}, expected #{src_len}")
      end

      # check output size
      if z.total_out != dst_len
        raise Error.new("write length mismatch (got #{z.total_out}, expected #{dst_len}")
      end

      # return number of bytes read
      dst_len
    end

    #
    # Inflate compressed data from ZStream and write it to given IO.
    #
    private def read_compressed(
      io    : IO,
      buf   : Bytes,
      zp    : Pointer(LibZ::ZStream),
      flush : Bool,
    )
      zf = flush ? LibZ::Flush::FINISH : LibZ::Flush::NO_FLUSH

      r, done = 0_u32, false
      while zp.value.avail_in > 0
        # set zlib output buffer
        zp.value.next_out = buf.to_unsafe
        zp.value.avail_out = buf.size.to_u32

        # inflate data, check for error
        case err = LibZ.inflate(zp, zf)
        when LibZ::Error::DATA_ERROR,
             LibZ::Error::NEED_DICT,
             LibZ::Error::MEM_ERROR
          # pp zp.value
          raise Zlib::Error.new(err, zp.value)
        when LibZ::Error::OK
          # do nothing
        when LibZ::Error::STREAM_END
          done = true
        end

        if ((len = buf.size - zp.value.avail_out) > 0)
          # write uncompressed data to io
          io.write((len < buf.size) ? Bytes.new(zp.value.next_out, len) : buf)
        end
      end

      # return number of unread bytes
      nil
    end
  end

  #
  # Classes for writing to output archives.
  #
  module Writers
    #
    # Abstract base class for classes used to store files and directories
    # for `Writer` instance.
    #
    abstract class WriterEntry
      include TimeHelper

      #
      # Is this a Zip64 entry?
      #
      getter? :zip64

      #
      # Constructor for abstract `WriterEntry` class.  You cannot
      # instantiate this class directly; use `Writer#add()`,
      # `Writer#add_file()` or `Writer#add_dir() instead.
      #
      def initialize(
        @pos      : UInt64,
        @path     : String,
        @method   : CompressionMethod = CompressionMethod::DEFLATE,
        @time     : Time = Time.now,
        @comment  : String = "",
        @flags    : GeneralFlags = GeneralFlags.flags(),
        @external : UInt32 = 0_u32,
        @zip64    : Bool = false,
      )
        @crc = 0_u32
        @src_len = 0_u64
        @dst_len = 0_u64

        # auto-enable zip64 if position is large enough
        @zip64 ||= (@pos >= UInt32::MAX)

        @extras = Extra.pack(if @zip64
          # build list of extras
          es = [] of Extra::Base

          # add zip64 to list of extras
          es << Extra::Zip64.new(
            size:             0_u64,
            compressed_size:  0_u64,
            pos:              (@pos >= UInt32::MAX) ? @pos : nil,
          )

          # return extras
          es
        else
          # no extras
          nil
        end)
      end

      #
      # Write local file entry to IO and return the number of bytes
      # written.
      #
      # You should not need to call this method directly; it is called
      # automatically by `Writer#add` and `Writer#add_file`.
      #
      def to_s(dst_io) : UInt64
        # write header
        r = write_header(dst_io, @flags, @path, @method, @time, @zip64)

        # write body
        @crc, @src_len, @dst_len = write_body(dst_io)
        r += @dst_len

        # write footer
        r += write_footer(dst_io, @crc, @src_len, @dst_len, @zip64)

        # return number of bytes written
        r
      end

      # :nodoc:
      # local file header signature     4 bytes  (0x04034b50)
      # version needed to extract       2 bytes
      # general purpose bit flag        2 bytes
      # compression method              2 bytes
      # last mod file time              2 bytes
      # last mod file date              2 bytes
      # crc-32                          4 bytes
      # compressed size                 4 bytes
      # uncompressed size               4 bytes
      # file name length                2 bytes
      # extra field length              2 bytes
      # file name (variable size)
      # extra field (variable size)
      # :nodoc:

      #
      # Write local header and return the number of bytes written.
      #
      private def write_header(
        io      : IO,
        flags   : GeneralFlags,
        path    : String,
        method  : CompressionMethod,
        time    : Time,
        zip64   : Bool,
      ) : UInt64
        # get path length, in bytes
        path_len = path.bytesize

        # check file path
        raise Error.new("empty file path") if path_len == 0
        raise Error.new("file path too long") if path_len >= UInt16::MAX
        raise Error.new("file path contains leading slash") if path[0] == '/'

        # write magic (u32), version needed (u16), flags (u16), and
        # compression method (u16)
        MAGIC[:file_header].to_u32.to_io(io, LE)
        Version::NEEDED.to_io(io)
        flags.to_u16.to_io(io, LE)
        method.to_u16.to_io(io, LE)

        # write time (u32)
        write_time(io, time)

        # write crc (u32)
        # (will be populated in the footer)
        0_u32.to_u32.to_io(io, LE)

        # write compressed size (u32) and uncompressed size (u32)
        # (will be populated in the footer)
        size = zip64? ? UInt32::MAX : 0_u32
        size.to_u32.to_io(io, LE)
        size.to_u32.to_io(io, LE)

        # write file path length (u16)
        path_len.to_u16.to_io(io, LE)

        # write extras field length (u16)
        extras_len = @extras.size
        extras_len.to_u16.to_io(io, LE)

        # write path field
        path.to_s(io)

        # write extra fields
        @extras.to_s(io) if extras_len > 0

        # return number of bytes written
        30_u64 + path_len + extras_len
      end

      abstract def write_body(dst_io : IO)

      abstract def write_footer(
        io      : IO,
        crc     : UInt32,
        src_len : UInt64,
        dst_len : UInt64,
        zip64   : Bool,
      ) : UInt32

      # :nodoc:
      # central file header signature   4 bytes  (0x02014b50)
      # version made by                 2 bytes
      # version needed to extract       2 bytes
      # general purpose bit flag        2 bytes
      # compression method              2 bytes
      # last mod file time              2 bytes
      # last mod file date              2 bytes
      # crc-32                          4 bytes
      # compressed size                 4 bytes
      # uncompressed size               4 bytes
      # file name length                2 bytes
      # extra field length              2 bytes
      # file comment length             2 bytes
      # disk number start               2 bytes
      # internal file attributes        2 bytes
      # external file attributes        4 bytes
      # relative offset of local header 4 bytes
      #
      # file name (variable size)
      # extra field (variable size)
      # file comment (variable size)
      # :nodoc:

      #
      # Write central directory data for this `WriterEntry` and return the
      # number of bytes written.
      #
      # You never need to call this method directly; it is called
      # automatically by `Writer#close`.
      #
      def write_central(
        io      : IO,
        version : Version = Version::DEFAULT,
      ) : UInt32
        MAGIC[:cdr_header].to_u32.to_io(io, LE)
        version.to_io(io)
        Version::NEEDED.to_io(io)
        @flags.to_u16.to_io(io, LE)
        @method.to_u16.to_io(io, LE)

        # write time
        write_time(io, @time)

        @crc.to_u32.to_io(io, LE)
        if zip64?
          UInt32::MAX.to_io(io, LE)
          UInt32::MAX.to_io(io, LE)
        else
          @dst_len.to_u32.to_io(io, LE)
          @src_len.to_u32.to_io(io, LE)
        end

        # get path length and write it
        path_len = @path.bytesize
        path_len.to_u16.to_io(io, LE)

        # write extras field length (u16)
        extras_len = @extras.size
        extras_len.to_u16.to_io(io, LE)

        # write comment field length (u16)
        comment_len = @comment.bytesize
        comment_len.to_u16.to_io(io, LE)

        # write disk number
        # TODO: add zip64 support
        0_u32.to_u16.to_io(io, LE)

        # write file attributes (internal, external)
        0_u32.to_u16.to_io(io, LE)
        @external.to_u32.to_io(io, LE)

        # write local header offset
        # TODO: add zip64 support
        @pos.to_u32.to_io(io, LE)

        # write path field
        @path.to_s(io)

        # write extra fields
        @extras.to_s(io) if extras_len > 0

        # write comment
        @comment.to_s(io)

        # return number of bytes written
        46_u32 + path_len + extras_len + comment_len
      end
    end

    #
    # Internal class used to store files for `Writer` instance.
    #
    # You should not need to instantiate this class directly; it is
    # called automatically by `Writer#add` and `Writer#add_file`.
    #
    class FileEntry < WriterEntry
      include NoneCompressionHelper
      include DeflateCompressionHelper

      #
      # Flags for local and central file header.
      #
      FLAGS = GeneralFlags.flags(FOOTER, EFS)

      #
      # Create a new FileWriterEntry instance.
      #
      # You should not need to call this method directly; it is called
      # automatically by `Writer#add` and `Writer#add_file`.
      #
      def initialize(
        pos     : UInt64,
        path    : String,
        @io     : IO,
        method  : CompressionMethod = CompressionMethod::DEFLATE,
        time    : Time = Time.now,
        comment : String = "",

        # FIXME: should this be true for unknown io?
        zip64   : Bool = false,
      )
        super(
          pos:      pos,
          path:     path,
          method:   method,
          time:     time,
          comment:  comment,
          flags:    FLAGS,
          external: 0_u32,
          zip64:    zip64,
        )
      end

      #
      # Write file contents and return the number of bytes written.
      #
      private def write_body(dst_io : IO)
        case @method
        when CompressionMethod::NONE
          compress_none(@io, dst_io)
        when CompressionMethod::DEFLATE
          compress_deflate(@io, dst_io)
        else
          raise Error.new("unsupported compression method: #{@method}")
        end
      end

      # :nodoc:
      #  4.3.9  Data descriptor:
      #       MAGIC = 0x08074b50              4 bytes
      #       crc-32                          4 bytes
      #       compressed size                 4 bytes
      #       uncompressed size               4 bytes
      #
      # 4.3.9.3 Although not originally assigned a signature, the value
      # 0x08074b50 has commonly been adopted as a signature value
      # :nodoc:

      #
      # Write file footer (data descriptor) and return the number of bytes
      # written.
      #
      private def write_footer(
        io      : IO,
        crc     : UInt32,
        src_len : UInt64,
        dst_len : UInt64,
        zip64   : Bool,
      ) : UInt32
        # write magic (u32)
        MAGIC[:file_footer].to_u32.to_io(io, LE)

        # write crc (u32), compressed size (u32), and full size (u32)
        crc.to_u32.to_io(io, LE)

        if zip64
          # write sizes as u64s
          dst_len.to_u64.to_io(io, LE)
          src_len.to_u64.to_io(io, LE)

          # return number of bytes written
          24_u32
        else
          # write sizes as u32s
          dst_len.to_u32.to_io(io, LE)
          src_len.to_u32.to_io(io, LE)

          # return number of bytes written
          16_u32
        end
      end
    end

    #
    # Internal class used to store files for `Writer` instance.
    #
    # You should not need to instantiate this class directly; use
    # `Writer#add_dir` instead.
    #
    class DirEntry < WriterEntry
      #
      # Default flags for local and central file header.
      #
      FLAGS = GeneralFlags.flags(EFS)

      #
      # Create a new DirEntry instance.
      #
      # You should not need to call this method directly; use
      # `Writer#add_dir` instead.
      #
      def initialize(
        pos     : UInt64,
        path    : String,
        time    : Time = Time.now,
        comment : String = "",
      )
        super(
          pos:      pos,
          path:     path,
          method:   CompressionMethod::NONE,
          time:     time,
          comment:  comment,
          flags:    FLAGS,
          external: 1_u32,
          zip64:    false,
        )
      end

      private def write_body(dst_io : IO)
        { 0_u32, 0_u64, 0_u64 }
      end

      private def write_footer(
        io      : IO,
        crc     : UInt32,
        src_len : UInt64,
        dst_len : UInt64,
        zip64   : Bool,
      ) : UInt32
        0_u32
      end
    end
  end

  #
  # Zip file writer.
  #
  # You shouldn't need to instantiate this class directly; use
  # `Zip.write()` instead.
  #
  class Writer
    #
    # Is this `Writer` closed?
    #
    getter? :closed

    #
    # Create a new `Writer` object.
    #
    # You shouldn't need to instantiate this class directly; use
    # `Zip.write()` instead.
    #
    def initialize(
      @io       : IO,
      @pos      : UInt64 = 0_u64,
      @comment  : String = "",
      @version  : Version = Version::DEFAULT,
    )
      @entries = [] of Writers::WriterEntry
      @closed = false
      @src_pos = @pos
    end

    private def assert_open
      raise Error.new("already closed") if closed?
    end

    #
    # Return the total number of bytes written so far.
    #
    # Example:
    #
    #     Zip.write("foo.zip") do |zip|
    #       # add "bar.txt"
    #       zip.add_file("bar.txt", "/path/to/bar.txt")
    #
    #       # print number of bytes written so far
    #       puts "bytes written so far: #{zip.bytes_written}"
    #     end
    #
    def bytes_written : UInt64
      # return total number of bytes written
      @src_pos - @pos
    end

    #
    # Close this writer and return the total number of bytes written.
    #
    def close
      assert_open

      # cache cdr position
      cdr_pos = @pos

      @entries.each do |entry|
        @pos += entry.write_central(@io, @version)
      end

      # write zip footer
      @pos += write_footer(cdr_pos, @pos - cdr_pos)

      # flag as closed
      @closed = true

      # return total number of bytes written
      bytes_written
    end

    private def add_entry(entry : Writers::WriterEntry) : UInt64
      # make sure writer is still open
      assert_open

      # add to list of entries
      @entries << entry

      # cache offset
      src_pos = @pos

      # write entry, update offset
      @pos += entry.to_s(@io)

      # return number of bytes written
      @pos - src_pos
    end

    #
    # Read data from `IO` *io*, write it to *path* in archive, then
    # return the number of bytes written.
    #
    # Example:
    #
    #     # create IO from "/path/to/bar.txt"
    #     File.open("/path/to/bar.txt, "rb") do |io|
    #       # write to "foo.zip"
    #       Zip.write("foo.zip") do |zip|
    #         # add "bar.txt" with contents of given IO
    #         zip.add("bar.txt", io)
    #       end
    #     end
    #
    def add(
      path    : String,
      io      : IO,
      method  : CompressionMethod = CompressionMethod::DEFLATE,
      time    : Time = Time.now,
      comment : String = "",

      # FIXME: should this be true for arbitrary IO?
      zip64   : Bool = false,
    ) : UInt64
      add_entry(Writers::FileEntry.new(
        pos:      @pos,
        path:     path,
        io:       io,
        method:   method,
        time:     time,
        comment:  comment,
        zip64:    zip64,
      ))
    end

    #
    # Write *data* to *path* in archive and return number of bytes
    # written.
    #
    # Example:
    #
    #     # write to "foo.zip"
    #     Zip.write("foo.zip") do |zip|
    #       # add "bar.txt" with contents "hello!"
    #       zip.add("bar.txt", "hello!")
    #     end
    #
    def add(
      path    : String,
      data    : String | Bytes,
      method  : CompressionMethod = CompressionMethod::DEFLATE,
      time    : Time = Time.now,
      comment : String = "",
    ) : UInt64
      zip64 = (data.size >= UInt32::MAX)
      add(path, IO::Memory.new(data), method, time, comment, zip64)
    end

    #
    # Add empty directory to archive as *path* and return number of
    # bytes written.
    #
    # Example:
    #
    #     # write to "foo.zip"
    #     Zip.write("foo.zip") do |zip|
    #       # add a directory named "example-dir"
    #       zip.add_dir("example-dir")
    #     end
    #
    def add_dir(
      path    : String,
      time    : Time = Time.now,
      comment : String = "",
    ) : UInt64
      add_entry(Writers::DirEntry.new(
        pos:      @pos,
        path:     path,
        time:     time,
        comment:  comment,
      ))
    end

    #
    # Add local file *file_path* to archive as *path* and return number
    # of bytes written.
    #
    # Example:
    #
    #     # write to "foo.zip"
    #     Zip.write("foo.zip") do |zip|
    #       # add local file "/path/to/bar.txt" as "bar.txt"
    #       zip.add_file("bar.txt", "/path/to/bar.txt")
    #     end
    #
    def add_file(
      path      : String,
      file_path : String,
      method    : CompressionMethod = CompressionMethod::DEFLATE,
      time      : Time = Time.now,
      comment   : String = "",
    ) : UInt64
      File.open(file_path, "rb") do |io|
        zip64 = (io.stat.size >= UInt32::MAX)
        add(path, io, method, time, comment, zip64)
      end
    end

    # :nodoc:
    # 4.3.16  End of central directory record:
    #
    # * end of central dir signature    4 bytes  (0x06054b50)
    # * number of this disk             2 bytes
    # * number of the disk with the
    #   start of the central directory  2 bytes
    # * total number of entries in the
    #   central directory on this disk  2 bytes
    # * total number of entries in
    #   the central directory           2 bytes
    # * size of the central directory   4 bytes
    # * offset of start of central
    #   directory with respect to
    #   the starting disk number        4 bytes
    # * .ZIP file comment length        2 bytes
    # * .ZIP file comment       (variable size)
    # :nodoc:

    private def write_footer(
      cdr_pos : UInt64,
      cdr_len : UInt64,
    ) : UInt64
      # write zip64 footer (if necessary)
      r = write_zip64_footer(cdr_pos, cdr_len)

      # write magic (u32)
      MAGIC[:cdr_footer].to_io(@io, LE)

      # write disk num (u16) and footer start disk (u16)
      0_u32.to_u16.to_io(@io, LE)
      0_u32.to_u16.to_io(@io, LE)

      # write number of entries (u16)
      num_entries = @entries.size
      if num_entries < UInt16::MAX
        # write num entries (u16) and total entries (u16)
        num_entries.to_u16.to_io(@io, LE)
        num_entries.to_u16.to_io(@io, LE)
      else
        # write max (defer to zip64 footer)
        UInt16::MAX.to_io(@io, LE)
        UInt16::MAX.to_io(@io, LE)
      end

      # write cdr offset (u32) and cdr length (u32)
      ((cdr_len < UInt32::MAX) ? cdr_len : UInt32::MAX).to_u32.to_io(@io, LE)
      ((cdr_pos < UInt32::MAX) ? cdr_pos : UInt32::MAX).to_u32.to_io(@io, LE)

      # get comment length (u16)
      comment_len = @comment.bytesize

      # write comment length (u16) and comment
      comment_len.to_u16.to_io(@io, LE)
      @comment.to_s(@io)

      # return number of bytes written
      r + 22_u64 + comment_len
    end

    # :nodoc:
    # 4.3.14  Zip64 end of central directory record
    #
    #      zip64 end of central dir
    #      signature                       4 bytes  (0x06064b50)
    #      size of zip64 end of central
    #      directory record                8 bytes
    #      version made by                 2 bytes
    #      version needed to extract       2 bytes
    #      number of this disk             4 bytes
    #      number of the disk with the
    #      start of the central directory  4 bytes
    #      total number of entries in the
    #      central directory on this disk  8 bytes
    #      total number of entries in the
    #      central directory               8 bytes
    #      size of the central directory   8 bytes
    #      offset of start of central
    #      directory with respect to
    #      the starting disk number        8 bytes
    #      zip64 extensible data sector    (variable size)
    #
    #    4.3.14.1 The value stored into the "size of zip64 end of central
    #    directory record" should be the size of the remaining
    #    record and should not include the leading 12 bytes.
    #
    #    Size = SizeOfFixedFields + SizeOfVariableData - 12.
    #
    #
    # 4.3.15 Zip64 end of central directory locator
    #
    #    zip64 end of central dir locator
    #    signature                       4 bytes  (0x07064b50)
    #    number of the disk with the
    #    start of the zip64 end of
    #    central directory               4 bytes
    #    relative offset of the zip64
    #    end of central directory record 8 bytes
    #    total number of disks           4 bytes
    # :nodoc:

    private def write_zip64_footer(
      cdr_pos : UInt64,
      cdr_len : UInt64,
    ) : UInt64
      # count entries
      num_entries = @entries.size

      if cdr_pos >= UInt32::MAX ||
         cdr_len >= UInt32::MAX ||
         num_entries >= UInt16::MAX
        z64_data_len = 0_u64

        ################
        # zip64 footer #
        ################

        # write magic (u32)
        MAGIC[:z64_footer].to_io(@io, LE)

        # write size (u64)
        (44_u64 + z64_data_len).to_io(@io, LE)

        # write version made by (u16)
        @version.to_io(@io)

        # write version needed (u16)
        Version::ZIP64.to_io(@io)

        # disk number (u32), disk with cdr (u32)
        0_u32.to_io(@io, LE)
        0_u32.to_io(@io, LE)

        # write number of entries (u64 x 2)
        num_entries.to_u64.to_io(@io, LE)
        num_entries.to_u64.to_io(@io, LE)

        # write cdr_len (u64)
        cdr_len.to_u64.to_io(@io, LE)

        # write cdr_pos (u64)
        cdr_pos.to_u64.to_io(@io, LE)

        # TODO: add z64_data

        #################
        # zip64 locator #
        #################

        # write magic (u32)
        MAGIC[:z64_locator].to_io(@io, LE)

        # write start disk (u32)
        0_u32.to_io(@io, LE)

        # write z64_cdr_pos (u64)
        (cdr_pos + cdr_len).to_u64.to_io(@io, LE)

        # write total number of disks (u32)
        1_u32.to_io(@io, LE)

        # return number of bytes written
        64_u64 + z64_data_len
      else
        # z64 header not needed
        0_u64
      end
    end
  end

  #
  # Create a `Zip::Writer` for the output IO *io* and yield it to
  # the given block.  Returns number of bytes written.
  #
  # Example:
  #
  #     # create output IO
  #     File.open("foo.zip", "wb") do |io|
  #       Zip.write(io) do |zip|
  #         # add "bar.txt" with contents "hello!"
  #         zip.add("bar.txt", "hello!")
  #       end
  #     end
  #
  def self.write(
    io      : IO,
    pos     : UInt64 = 0_u64,
    comment : String = "",
    version : Version = Version::DEFAULT,
    &cb     : Writer -> \
  ) : UInt64
    r = 0_u64

    begin
      w = Writer.new(io, pos, comment, version)
      cb.call(w)
    ensure
      if w
        w.close unless w.closed?
        r = w.bytes_written
      end
    end

    # return total number of bytes written
    r
  end

  #
  # Create a `Zip::Writer` for the output file *path* and yield it to
  # the given block.  Returns number of bytes written.
  #
  # Example:
  #
  #     # create "foo.zip"
  #     Zip.write("foo.zip") do |zip|
  #       # add "bar.txt" with contents "hello!"
  #       zip.add("bar.txt", "hello!")
  #     end
  #
  def self.write(
    path    : String,
    pos     : UInt64 = 0_u64,
    comment : String = "",
    version : Version = Version::DEFAULT,
    &cb     : Writer -> \
  ) : UInt64
    File.open(path, "wb") do |io|
      write(io, pos, comment, version, &cb)
    end
  end

  #
  # Base class for input source for `Archive` object.
  #
  # You should not need to instantiate this class directly; use
  # `Zip.read()` instead.
  #
  class Source
    include IO

    #
    # Instantiate a new `Source` from the given `IO::FileDescriptor` or
    # `IO::Memory` object.
    #
    # You should not need to instantiate this class directly; use
    # `Zip.read()` instead.
    #
    def initialize(@io : IO::FileDescriptor | IO::Memory)
    end

    delegate read, to: @io
    delegate write, to: @io
    forward_missing_to @io
  end

  #
  # File entry in `Archive`.
  #
  # Use `Zip.read()` to read a Zip archive, then `#[]` to fetch a
  # specific archive entry.
  #
  # Example:
  #
  #     # create IO::Memory
  #     io = IO::Memory.new
  #
  #     # open "foo.zip"
  #     Zip.read("foo.zip") do |zip|
  #       # get "bar.txt" entry from "foo.zip"
  #       e = zip["bar.txt"]
  #
  #       # read contents of "bar.txt" into io
  #       e.read(io)
  #     end
  #
  class Entry
    include TimeHelper
    include NoneCompressionHelper
    include DeflateCompressionHelper

    #
    # Get `Version` used to generate this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print version used for each entry
    #       zip.each do |e|
    #         puts "#{e.path} version used: #{e.version}"
    #       end
    #     end
    #
    getter :version

    #
    # Get `Version` needed to generate this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print version needed to extract each entry
    #       zip.each do |e|
    #         puts "#{e.path} version needed: #{e.version_needed}"
    #       end
    #     end
    #
    getter :version_needed

    #
    # Get `GeneralFlags` for this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print flags for each entry
    #       zip.each do |e|
    #         puts "#{e.path} flags: #{e.flags}"
    #       end
    #     end
    #
    getter :flags

    #
    # Get `CompressionMethod` for this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print compression method for each entry
    #       zip.each do |e|
    #         puts "#{e.path} compression method: #{e.method}"
    #       end
    #     end
    #
    getter :method

    #
    # Get `Time` for this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print time for each entry
    #       zip.each do |e|
    #         puts "#{e.path} time: #{e.time}"
    #       end
    #     end
    #
    getter :time

    #
    # Get CRC-32 for this `Entry` as a `UInt32`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print crc for each entry
    #       zip.each do |e|
    #         puts "#{e.path} CRC-32: #{e.crc}"
    #       end
    #     end
    #
    getter :crc

    #
    # Get compressed size for this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print compressed size for each entry
    #       zip.each do |e|
    #         puts "#{e.path} compressed size: #{e.compressed_size}"
    #       end
    #     end
    #
    getter :compressed_size

    #
    # Get uncompressed size for this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print uncompressed size for each entry
    #       zip.each do |e|
    #         puts "#{e.path} uncompressed size: #{e.size}"
    #       end
    #     end
    #
    getter :size

    #
    # Get path for this `Entry` as a `String`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print uncompressed size for each entry
    #       zip.each do |e|
    #         puts "#{e.path}"
    #       end
    #     end
    #
    getter :path

    #
    # Get `Extra` data for this `Entry` as an `Array`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print number of extra data items for each entry
    #       zip.each do |e|
    #         puts "#{e.path} extras: #{e.extras.size}"
    #       end
    #     end
    #
    getter :extras

    #
    # Get comment for this `Entry` as a `String`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print comment for each entry
    #       zip.each do |e|
    #         puts "#{e.path} comment: #{e.comment}"
    #       end
    #     end
    #
    getter :comment

    #
    # Get internal attributes for this `Entry` as a `UInt16`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print internal attributes for each entry
    #       zip.each do |e|
    #         puts "#{e.path} internal attributes: #{e.internal}"
    #       end
    #     end
    #
    getter :internal

    #
    # Get external attributes for this `Entry` as a `UInt32`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print external attributes for each entry
    #       zip.each do |e|
    #         puts "#{e.path} external attributes: #{e.external}"
    #       end
    #     end
    #
    getter :external

    #
    # Get position for this `Entry`.
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print position for each entry
    #       zip.each do |e|
    #         puts "#{e.path} position: #{e.pos}"
    #       end
    #     end
    #
    getter :pos

    # :nodoc:
    # central file header signature   4 bytes  (0x02014b50)
    # version made by                 2 bytes
    # version needed to extract       2 bytes
    # general purpose bit flag        2 bytes
    # compression method              2 bytes
    # last mod file time              2 bytes
    # last mod file date              2 bytes
    # crc-32                          4 bytes
    # compressed size                 4 bytes
    # uncompressed size               4 bytes
    # file name length                2 bytes
    # extra field length              2 bytes
    # file comment length             2 bytes
    # disk number start               2 bytes
    # internal file attributes        2 bytes
    # external file attributes        4 bytes
    # relative offset of local header 4 bytes
    #
    # file name (variable size)
    # extra field (variable size)
    # file comment (variable size)
    # :nodoc:

    #
    # Instantiate a new `Entry` object from the given IO.
    #
    # You should not need to call this method directly (use
    # `Zip::Archive#[]` instead).
    #
    def initialize(@io : Source)
      # allocate slice for header data
      head_buf = Bytes.new(46)

      # read entry
      if ((head_len = io.read_fully(head_buf)) != 46)
        raise Error.new("couldn't read full CDR entry (#{head_len} != 46)")
      end

      # create memory io for slice
      head_mem_io = IO::Memory.new(head_buf, false)

      magic = UInt32.from_io(head_mem_io, LE)
      if magic != MAGIC[:cdr_header]
        raise Error.new("invalid CDR header magic")
      end

      # read versions
      @version = UInt16.from_io(head_mem_io, LE).as(UInt16)
      @version_needed = UInt16.from_io(head_mem_io, LE).as(UInt16)

      # TODO: check versions

      # read flags, method, and date
      @flags = UInt16.from_io(head_mem_io, LE).as(UInt16)
      @method = CompressionMethod.new(
        UInt16.from_io(head_mem_io, LE).as(UInt16).to_i32
      )

      # TODO: convert to Time object
      @time = from_dos_time(UInt32.from_io(head_mem_io, LE)).as(Time)

      # read crc and lengths
      # (store lengths as u64 for zip64 compat)
      @crc = UInt32.from_io(head_mem_io, LE).as(UInt32)
      @compressed_size = UInt32.from_io(head_mem_io, LE).to_u64.as(UInt64)
      @size = UInt32.from_io(head_mem_io, LE).to_u64.as(UInt64)

      # read lengths
      @path_len = UInt16.from_io(head_mem_io, LE).not_nil!.as(UInt16)
      @extras_len = UInt16.from_io(head_mem_io, LE).as(UInt16)
      @comment_len = UInt16.from_io(head_mem_io, LE).as(UInt16)

      # read starting disk
      # (store as u32 for zip64 compat)
      @disk_start = UInt16.from_io(head_mem_io, LE).to_u32.as(UInt32)

      # read attributes and position
      @internal = UInt16.from_io(head_mem_io, LE).as(UInt16)
      @external = UInt32.from_io(head_mem_io, LE).as(UInt32)

      # read position
      # (store as u64 for zip64 compat)
      @pos = UInt32.from_io(head_mem_io, LE).to_u64.as(UInt64)

      # close memory io
      head_mem_io.close

      # create data buffer
      # (holds path, extras, and comment data)
      data_len = @path_len + @extras_len + @comment_len
      data_buf = Bytes.new(data_len)

      begin
        # populate data buffer
        io.read_fully(data_buf)
      rescue
        raise Error.new("couldn't read entry CDR name, extras, and comment")
      end

      # create data memory io
      data_mem_io = IO::Memory.new(data_buf)

      # read path, extras, and comment from data memory io
      @path = read_string(data_mem_io, @path_len, "name").as(String)
      @extras = read_extras(data_mem_io, @extras_len).as(Array(Extra::Base))
      @comment = read_string(data_mem_io, @comment_len, "comment").as(String)

      if e = @extras.find { |e| e.code == Extra::Zip64::CODE }
        e = e.as(Extra::Zip64)
        @size = e.size
        @compressed_size = e.compressed_size
        @pos = e.pos.not_nil! if e.pos
        @disk_start = e.disk_start.not_nil! if e.disk_start
      end

      # close data memory io
      data_mem_io.close
    end

    #
    # Returns true if this entry a directory.
    #
    # Example:
    #
    #     Zip.read("foo.zip") do |zip|
    #       type = zip["some-dir/"].dir? ? "directory" : "file"
    #       puts "#{path} is a #{type}"
    #     end
    #
    def dir? : Bool
      (@external & 0x01) != 0
    end

    # :nodoc:
    # local file header signature     4 bytes  (0x04034b50)
    # version needed to extract       2 bytes
    # general purpose bit flag        2 bytes
    # compression method              2 bytes
    # last mod file time              2 bytes
    # last mod file date              2 bytes
    # crc-32                          4 bytes
    # compressed size                 4 bytes
    # uncompressed size               4 bytes
    # file name length                2 bytes
    # extra field length              2 bytes
    # file name (variable size)
    # extra field (variable size)
    # :nodoc:

    #
    # Write contents of `Entry` into given `IO`.
    #
    # Raises an `Error` if the file contents could not be read or if the
    # compression method is unsupported.
    #
    # Example:
    #
    #     # open "output-bar.txt" for writing
    #     File.open("output-bar.txt", "wb") do |io|
    #       # open archive "./foo.zip"
    #       Zip.read("foo.zip") do |zip|
    #         # write contents of "bar.txt" to "output-bar.txt"
    #         zip["foo.txt"].write(io)
    #       end
    #     end
    #
    def write(dst_io : IO) : UInt64
      # create buffer for local header
      buf = Bytes.new(30)

      # move to local header
      @io.pos = @pos

      # read local header into buffer
      @io.read_fully(buf)

      # create memory io from buffer
      mem_io = IO::Memory.new(buf, false)

      # check magic header
      magic = UInt32.from_io(mem_io, LE)
      if magic != MAGIC[:file_header]
        raise Error.new("invalid file header magic")
      end

      # skip local header
      mem_io.pos = 26_u32

      # read local name and extras length
      path_len = UInt16.from_io(mem_io, LE)
      extras_len = UInt16.from_io(mem_io, LE)

      # close memory io
      mem_io.close

      # skip name and extras
      @io.pos = @pos + 30_u32 + path_len + extras_len

      case @method
      when CompressionMethod::NONE
        decompress_none(@io, dst_io, @compressed_size, @size)
      when CompressionMethod::DEFLATE
        decompress_deflate(@io, dst_io, @compressed_size, @size)
      else
        raise Error.new("unsupported method: #{@method}")
      end

      # return number of bytes written
      @size
    end

    #
    # Write contents of `Entry` into given path *path* and return the
    # number of bytes written.
    #
    # Raises an `Error` if the file contents could not be read or if the
    # compression method is unsupported.
    #
    # Example:
    #
    #     # open "output-bar.txt" for writing
    #     File.open("output-bar.txt", "wb") do |io|
    #       # open archive "./foo.zip"
    #       Zip.read("foo.zip") do |zip|
    #         # write contents of "bar.txt" to "output-bar.txt"
    #         zip["foo.txt"].write(io)
    #       end
    #     end
    #
    def write(path : String) : UInt64
      File.open(path, "wb") do |io|
        write(io)
      end
    end

    #
    # Returns an array of `Extra` attributes for this `Entry`.
    #
    # Zip archives can (and do) have separate `Extra` attributes
    # associated with the file entry itself, and the file's entry in the
    # Central Directory.
    #
    # The `#extras` method returns the `Extra` attributes from the
    # file's entry in the Central Directory, and this method returns the
    # `Extra` data from the file entry itself.
    #
    # Example:
    #
    #     # open "./foo.zip"
    #     Zip.read("./foo.zip") do |zip|
    #       # get array of local extra attributes from "bar.txt"
    #       extras = zip["bar.txt"].local_extras
    #     end
    #
    def local_extras : Array(Extra::Base)
      unless @local_extras
        # move to extras_len in local header
        @io.pos = @pos + 26_u32

        # read name and extras lengths
        name_len = UInt16.from_io(@io, LE)
        extras_len = UInt16.from_io(@io, LE)

        # move to extras_len in local header
        @io.pos = @pos + 30_u32 + name_len

        # read local extras
        @local_extras = read_extras(@io, extras_len).as(Array(Extra::Base))
      end

      # return results
      @local_extras.not_nil!
    end

    #
    # Returns an array of `Extra` attributes of length `len` from IO `io`.
    #
    private def read_extras(io, len : UInt16) : Array(Extra::Base)
      # read extras
      r = [] of Extra::Base

      if len > 0
        # create buffer of extras data
        buf = Bytes.new(len)
        if io.read_fully(buf) != len
          raise Error.new("couldn't read CDR entry extras")
        end

        # create memory io over buffer
        mem_io = IO::Memory.new(buf, false)

        # read extras from io
        while mem_io.pos != mem_io.size
          r << Extra.read(mem_io)
        end

        # close memory io
        mem_io.close
      end

      # return results
      r
    end

    #
    # Read String of length bytes from IO.
    #
    # Note: At the moment this assumes UTF-8 encoding, but we should
    # make this configurable via a parameter to `#read()`.
    #
    private def read_string(io, len : UInt16, name : String) : String
      if len > 0
        buf = Bytes.new(len)

        if io.read_fully(buf) != len
          raise Error.new("couldn't read CDR entry #{name}")
        end

        # FIXME: should handle encoding here?
        String.new(buf)
      else
        ""
      end
    end
  end

  # :nodoc:
  # 4.3.16  End of central directory record:
  #
  # * end of central dir signature    4 bytes  (0x06054b50)
  # * number of this disk             2 bytes
  # * number of the disk with the
  #   start of the central directory  2 bytes
  # * total number of entries in the
  #   central directory on this disk  2 bytes
  # * total number of entries in
  #   the central directory           2 bytes
  # * size of the central directory   4 bytes
  # * offset of start of central
  #   directory with respect to
  #   the starting disk number        4 bytes
  # * .ZIP file comment length        2 bytes
  # * .ZIP file comment       (variable size)
  # :nodoc:

  #
  # Input archive.
  #
  # Use `Zip.read()` instead of instantiating this class directly.
  #
  class Archive
    include Enumerable(Entry)
    include Iterable(Entry)

    #
    # Return an array of entries in this Archive.
    #
    # Example:
    #
    #     Zip.read("foo.zip") do |zip|
    #       # get an array of entries in this archive
    #       entries = zip.entries
    #     end
    #
    getter :entries

    #
    # Get the `Archive` comment as a String.
    #
    # Example:
    #
    #     Zip.read("foo.zip") do |zip|
    #       # print archive comment
    #       puts "comment: #{zip.comment}"
    #     end
    #
    getter :comment

    #
    # Create new Zip::Archive from input Zip::Source.
    #
    # Use `Zip.read()` instead of calling this method directly.
    #
    def initialize(@io : Source)
      # initialize entries
      # find footer and end of io
      footer_pos, end_pos = find_footer_and_eof(@io)

      # skip magic
      @io.pos = footer_pos + 4

      # create slice and memory io
      mem = Bytes.new(18)

      # read footer into memory io
      @io.pos = footer_pos + 4
      if ((len = @io.read_fully(mem)) < mem.size)
        raise Error.new("couldn't read zip footer")
      end

      # create memory io for slice
      mem_io = IO::Memory.new(mem, false)

      # read disk numbers
      # (convert to u32 so type matches zip64 values)
      @disk_num = UInt16.from_io(mem_io, LE).to_u32.as(UInt32)
      @cdr_disk = UInt16.from_io(mem_io, LE).to_u32.as(UInt32)

      # read entry counts
      # (convert to u64 so type matches zip64 values)
      @num_disk_entries = UInt16.from_io(mem_io, LE).to_u64.as(UInt64)
      @num_entries = UInt16.from_io(mem_io, LE).to_u64.as(UInt64)

      # read cdr position and length
      # (convert to u64 so type matches zip64 values)
      @cdr_len = UInt32.from_io(mem_io, LE).to_u64.as(UInt64)
      @cdr_pos = UInt32.from_io(mem_io, LE).to_u64.as(UInt64)

      # read comment length and comment body
      @comment_len = UInt16.from_io(mem_io, LE).as(UInt16)
      @comment = if @comment_len > 0
        # allocate space for comment
        slice = Bytes.new(@comment_len)

        # seek to comment position
        @io.pos = footer_pos + 22

        # read comment data
        if ((len = @io.read_fully(slice)) != @comment_len)
          raise Error.new("archive comment read truncated")
        end

        # FIXME: shouldn't assume UTF-8 here
        String.new(slice, "UTF-8")
      else
        ""
      end

      # close memory io
      mem_io.close

      # check and see if any of the footer entries are 0xFFFF or
      # 0xFFFFFFFF (that is, they indicate a zip64 header)
      if @disk_num == UInt16::MAX || @cdr_disk == UInt16::MAX ||
         @num_disk_entries == UInt16::MAX || @num_entries == UInt16::MAX ||
         @cdr_len == UInt32::MAX || @cdr_pos == UInt32::MAX
        # create buffer and mem_io for zip64 header
        buf = Bytes.new(56)
        mem_io = IO::Memory.new(buf, false)

        # seek to zip64 footer position and read it in
        z64_pos = find_zip64_footer(@io, footer_pos)
        @io.read_fully(buf)

        # read and check magic
        magic = UInt32.from_io(mem_io, LE)
        if magic != MAGIC[:z64_footer]
          raise Error.new("invalid ZIP64 footer magic")
        end

        # read zip64 footer length and calculate data len
        # (footer length value excludes magic and length)
        z64_len = UInt64.from_io(mem_io, LE)
        @zip64_data_len = z64_len - 44

        # read versions
        @version = Version.new(UInt16.from_io(mem_io, LE))
        @version_needed = Version.new(UInt16.from_io(mem_io, LE))

        # read disk numbers
        @disk_num = UInt32.from_io(mem_io, LE).to_u32
        @cdr_disk = UInt32.from_io(mem_io, LE).to_u32

        # read entry counts
        @num_disk_entries = UInt64.from_io(mem_io, LE)
        @num_entries = UInt64.from_io(mem_io, LE)

        # read cdr position and length
        @cdr_len = UInt64.from_io(mem_io, LE)
        @cdr_pos = UInt64.from_io(mem_io, LE)

        # close memory io
        mem_io.close

        # read zip64 data
        @zip64_data = if @zip64_data_len > 0
          # create buffer
          z64_data_buf = Bytes.new(@zip64_data_len)

          # skip to data position and read it in
          @io.pos = z64_pos + 56
          @io.read_fully(z64_data_buf)

          # return buffer
          z64_data_buf
        else
          EMPTY_SLICE
        end
      else
        # set version and version_needed to default
        @version = Version::DEFAULT
        @version_needed = Version::DEFAULT

        # no zip64 data for non-zip64 archives
        @zip64_data_len = 0_u64
        @zip64_data = EMPTY_SLICE
      end

      ########################
      # verify header values #
      ########################

      # check disk numbers
      if @disk_num != @cdr_disk
        raise Error.new("multi-disk archives not supported")
      end

      # check entry counts
      if @num_disk_entries != @num_entries
        raise Error.new("multi-disk archives not supported")
      end

      # check cdr position
      if @cdr_pos + @cdr_len >= end_pos
        raise Error.new("invalid CDR offset: #{@cdr_pos}")
      end

      # read entries
      @entries = [] of Entry
      read_entries(@entries, @io, @cdr_pos, @cdr_len, @num_entries)
    end

    #################################
    # enumeration/iteration methods #
    #################################

    #
    # Get hash of path -> Zip::Entries
    #
    private def paths
      @paths ||= @entries.reduce({} of String => Entry) do |r, e|
        r[e.path] = e
        r
      end.as(Hash(String, Entry))
    end

    #
    # Get Zip::Entry by path.
    #
    # Example:
    #
    #     # get bar.txt and write it into memory io
    #     io = IO::Memory.new
    #     zip["bar.txt"].write(io)
    #
    def [](path : String) : Entry
      paths[path]
    end

    #
    # Return Zip::Entry from path, or nil if it doesn't exist.
    #
    # Example:
    #
    #     # write contents of "bar.txt" into memory io if it exists
    #     if e = zip["bar.txt"]?
    #       io = IO::Memory.new
    #       e.write(io)
    #     end
    #
    def []?(path : String) : Entry?
      paths[path]?
    end

    #
    # Get Zip::Entry by number.
    #
    # Example:
    #
    #     # write contents of third entry from archive into memory io
    #     io = IO::Memory.new
    #     zip[2].write(io)
    #
    def [](id : Int) : Entry
      @entries[id]
    end

    #
    # Get Zip::Entry by number, or nil if it doesn't exist
    #
    # Example:
    #
    #     # write contents of third entry from archive into memory io
    #     if e = zip[2]?
    #       io = IO::Memory.new
    #       e.write(io)
    #     end
    #
    def []?(id : Int) : Entry?
      @entries[id]?
    end

    #
    # Iterate over the entries in this `Archive`, or, if called without
    # a block, return a lazy iterator.
    #
    # Example:
    #
    #     Zip.read("foo.zip") do |zip|
    #       zip.each do |e|
    #         type = e.dir? ? "directory" : "file"
    #         puts "#{e.path} is a #{type}"
    #       end
    #     end
    #
    delegate each, to: @entries

    #
    # Return the number of entries in this `Archive`.
    #
    # Example:
    #
    #     Zip.read("foo.zip") do |zip|
    #       puts "foo.zip has #{zip.size} entries"
    #     end
    #
    delegate size, to: @entries

    ###################
    # loading methods #
    ###################

    #
    # Read CDR entries from given `Zip::Source`.
    #
    private def read_entries(
      entries     : Array(Entry),
      io          : Source,
      cdr_pos     : UInt64,
      cdr_len     : UInt64,
      num_entries : UInt64,
    )
      # get end position
      end_cdr_pos = cdr_pos + cdr_len

      # seek to start of entries
      io.pos = cdr_pos

      # read entries
      num_entries.times do |i|
        # create new entry
        entry = Entry.new(io)

        # add to list of entries
        entries << entry

        # check position
        if io.pos > end_cdr_pos
          raise Error.new("read past CDR")
        end
      end
    end

    #
    # Find EOF and end of CDR for archive.
    #
    private def find_footer_and_eof(io : Source)
      # seek to end of file
      io.seek(0, IO::Seek::End)
      end_pos = io.pos

      if end_pos < 22
        raise Error.new("too small for end of central directory")
      end

      # create buffer and memory io around it
      buf = Bytes.new(22)
      mem_io = IO::Memory.new(buf, false)

      curr_pos = end_pos - 22
      while curr_pos >= 0
        # seek to current position and load possible cdr into buffer
        io.pos = curr_pos
        io.read_fully(buf)

        # rewind memory io
        mem_io.rewind

        # read what might be the end_cdr magic
        maybe_end_magic = UInt32.from_io(mem_io, LE)

        if maybe_end_magic == MAGIC[:cdr_footer]
          # jump to archive commment len (maybe)
          mem_io.pos = 20

          # get archive commment len (maybe)
          maybe_comment_len = UInt16.from_io(mem_io, LE)

          if curr_pos + 22 + maybe_comment_len == end_pos
            # close memio
            mem_io.close

            # magic and comment line up: probably found end_cdr
            return { curr_pos, end_pos }
          end
        end

        # step back one byte
        curr_pos -= 1
      end

      # throw error
      raise Error.new("couldn't find end of central directory")
    end

    private def find_zip64_footer(io : Source, footer_pos : Int) : UInt64
      buf = Bytes.new(20)
      mem_io = IO::Memory.new(buf, false)

      curr_pos = footer_pos - 20
      while curr_pos >= 0
        # seek to current position and read it into buffer
        io.pos = curr_pos
        io.read_fully(buf)

        # read what might be the zip64 locator magic
        maybe_magic = UInt32.from_io(mem_io, LE)

        if maybe_magic == MAGIC[:z64_locator]
          z64_start_disk = UInt32.from_io(mem_io, LE)
          z64_pos = UInt64.from_io(mem_io, LE)
          z64_num_disks = UInt32.from_io(mem_io, LE)

          # check disk counts
          if z64_start_disk > 1 || z64_num_disks > 1
            raise Error.new("multi-disk ZIP64 archives not supported")
          end

          # return position of zip64 footer
          return z64_pos
        end

        # step back one byte
        curr_pos -= 1
      end

      # throw error
      raise Error.new("couldn't find ZIP64 locator")
    end
  end

  #
  # Read Zip::Archive from seekable IO instance and pass it to the given
  # block.
  #
  # Example:
  #
  #     # create memory io for contents of "bar.txt"
  #     io = IO::Memory.new
  #
  #     # read "bar.txt" from "foo.zip"
  #     Zip.read(File.open("foo.zip", "rb")) do |zip|
  #       zip["bar.txt"].write(io)
  #     end
  #
  def self.read(
    io          : IO,
    &cb         : Archive -> \
  ) : Void
    r = Archive.new(Source.new(io))
    cb.call(r)
  end

  #
  # Read Zip::Archive from Slice and pass it to the given block.
  #
  # Example:
  #
  #     # create memory io for contents of "bar.txt"
  #     io = IO::Memory.new
  #
  #     # extract "bar.txt" from zip archive in Slice some_slice and
  #     # save it to IO::Memory
  #     Zip.read(some_slice) do |zip|
  #       zip["bar.txt"].write(io)
  #     end
  #
  def self.read(
    slice : Bytes,
    &cb   : Archive -> \
  ) : Void
    src = Source.new(IO::Memory.new(slice, false))
    read(src, &cb)
  end

  #
  # Read Zip::Archive from File and pass it to the given block.
  #
  # Example:
  #
  #     # create memory io for contents of "bar.txt"
  #     io = IO::Memory.new
  #
  #     # extract "bar.txt" from "foo.zip" and save it to IO::Memory
  #     Zip.read("foo.zip") do |zip|
  #       zip["bar.txt"].write(io)
  #     end
  #
  def self.read(
    path : String,
    &cb  : Archive -> \
  ) : Void
    File.open(path, "rb") do |io|
      read(io, &cb)
    end
  end
end
