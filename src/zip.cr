require "./zip/*"
require "zlib"

#
# TODO:
# [x] date/time
# [ ] reader
# [ ] documentation
# [ ] full tests
# [ ] zip64
# [ ] legacy unicode (e.g., non-bit 11) path/comment support
# [ ] extra data
# [ ] unix uids
# [ ] bzip2/lzma support
#

module Zip
  VERSION = "0.1.0"

  MAGIC = {
    cdr_header:   0x02014b50_u32,
    cdr_footer:   0x06054b50_u32,
    file_header:  0x04034b50_u32,
    file_footer:  0x08074b50_u32,
  }

  LE = IO::ByteFormat::LittleEndian

  # size of buffers, in bytes
  BUFFER_SIZE = 8192

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
  #
  @[Flags]
  enum GeneralFlags
    ENCRYPTION
    COMPRESSION_OPTION_1
    COMPRESSION_OPTION_2
    FOOTER
    RESERVED_4
    PATCH
    STRONG_ENCRYPTION
    RESERVED_7
    RESERVED_8
    RESERVED_9
    RESERVED_10
    EFS
    RESERVED_12
    MASKED_VALUES
    RESERVED_14
    RESERVED_15
  end

  enum CompressionMethod
    NONE = 0            # Stored (no compression)
    SHRUNK = 1          # Shrunk
    REDUCED_1 = 2       # Reduced with compression factor 1
    REDUCED_2 = 3       # Reduced with compression factor 2
    REDUCED_3 = 4       # Reduced with compression factor 3
    REDUCED_4 = 5       # Reduced with compression factor 4
    IMPLODED = 6        # Imploded
    # Tokenized = 7       # Reserved for Tokenizing compression algorithm
    DEFLATE = 8         # Deflated
    DEFLATE64 = 9       # Enhanced Deflating using Deflate64(tm)
    TERSE_OLD = 10      # PKWARE Data Compression Library Imploding (old IBM TERSE)
    # RESERVED_11 = 11    # Reserved by PKWARE
    BZIP2 = 12          # BZIP2
    # RESERVED_13 = 13  # Reserved by PKWARE
    LZMA = 14           # LZMA (EFS)
    # RESERVED_15 = 15    # Reserved by PKWARE
    # RESERVED_16 = 16    # Reserved by PKWARE
    # RESERVED_17 = 17    # Reserved by PKWARE
    TERSE = 18          # IBM TERSE (new)
    LZ77 = 19           # IBM LZ77 z Architecture (PFS)
    WAVPACK = 97        # WavPack compressed data
    PPMD = 98           # PPMd version I, Rev 1
  end

  # FIXME: should this have a better class?
  class Error < Exception
  end

  module TimeHelper
    def write_time(io : IO, time : Time) : UInt32
      year = Math.max(1980, time.year) - 1980

      # convert to dos timestamp
      ((
        (year << 25) | (time.month << 21) | (time.day << 16) |
        (time.hour << 11) | (time.minute << 5) | (time.second >> 1)
      ) & UInt32::MAX).to_u32.to_io(io, LE)

      # return number of bytes written
      4_u32
    end
  end

  module NoneCompressionHelper
    def compress_none(src_io, dst_io)
      crc = 0_u32

      buf = Bytes.new(BUFFER_SIZE)
      src_len = 0_u32

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
  end

  module DeflateCompressionHelper
    ZALLOC_PROC = LibZ::AllocFunc.new do |data, num_items, size|
      GC.malloc(num_items * size)
    end

    ZFREE_PROC = LibZ::FreeFunc.new do |data, addr|
      GC.free(addr)
    end

    ZLIB_VERSION = LibZ.zlibVersion

    def compress_deflate(src_io, dst_io)
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
        write_compressed(dst_io, dst_buf, pointerof(z), false)
      end

      # set zlib input buffer to null
      z.next_in = Pointer(UInt8).null
      z.avail_in = 0_u32

      # flush remaining data
      write_compressed(dst_io, dst_buf, pointerof(z), true)

      # free stream
      LibZ.deflateEnd(pointerof(z))

      # return results
      { crc.to_u32, z.total_in.to_u32, z.total_out.to_u32 }
    end

    private def write_compressed(
      io    : IO,
      buf   : Bytes,
      zp    : Pointer(LibZ::ZStream),
      flush : Bool,
    )
      zf = flush ? LibZ::Flush::FINISH : LibZ::Flush::NO_FLUSH

      loop do
        # set zlib output buffer
        zp.value.next_out = buf.to_unsafe
        zp.value.avail_out = buf.size.to_u32

        # compress data (TODO: check for error)
        LibZ.deflate(zp, zf)

        if ((len = buf.size - zp.value.avail_out) > 0)
          # write compressed buffer to dst io
          io.write((len < buf.size) ? buf[0, len] : buf)
        end

        # exit loop if there is no remaining space
        break if zp.value.avail_out != 0
      end
    end
  end

  class WriterEntry
    include TimeHelper
    include NoneCompressionHelper
    include DeflateCompressionHelper

    # version needed to extract and header flags (4.4.3.2)
    # (used for local header and central header)
    VERSION_NEEDED = 45_u32
    GENERAL_FLAGS = GeneralFlags.flags(FOOTER, EFS)

    def initialize(
      @pos      : UInt32,
      @path     : String,
      @io       : IO,
      @method   : CompressionMethod = CompressionMethod::DEFLATE,
      @time     : Time = Time.now,
      @comment  : String = "",
    )
      @crc = 0_u32
      @src_len = 0_u32
      @dst_len = 0_u32
    end

    def to_s(dst_io) : UInt32
      # write header
      r = write_header(dst_io, @path, @method, @time)

      # write body
      @crc, @src_len, @dst_len = write_body(dst_io)
      r += @dst_len

      # write footer
      r += write_footer(dst_io, @crc, @src_len, @dst_len)

      # return number of bytes written
      r
    end

    #
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
    #

    private def write_header(
      io      : IO,
      path    : String,
      method  : CompressionMethod,
      time    : Time,
    ) : UInt32
      # get path length, in bytes
      path_len = path.bytesize

      # check file path
      raise Error.new("empty file path") if path_len == 0
      raise Error.new("file path too long") if path_len >= UInt16::MAX
      raise Error.new("file path contains leading slash") if path[0] == '/'

      # write magic (u32), version needed (u16), flags (u16), and
      # compression method (u16)
      MAGIC[:file_header].to_u32.to_io(io, LE)
      VERSION_NEEDED.to_u16.to_io(io, LE)
      GENERAL_FLAGS.to_u16.to_io(io, LE)
      method.to_u16.to_io(io, LE)

      # write time (u32)
      write_time(io, time)

      # crc (u32), compressed size (u32), uncompressed size (u32)
      # (these will be populated in the footer)
      0_u32.to_u32.to_io(io, LE)
      0_u32.to_u32.to_io(io, LE)
      0_u32.to_u32.to_io(io, LE)

      # write file path length (u16)
      path_len.to_u16.to_io(io, LE)

      # write extras field length (u16)
      extras_len = 0_u32
      extras_len.to_u16.to_io(io, LE)

      # write path field
      path.to_s(io)

      # write extra fields
      # TODO: implement this

      # return number of bytes written
      30_u32 + path_len + extras_len
    end

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

    #  4.3.9  Data descriptor:
    #       MAGIC = 0x08074b50              4 bytes
    #       crc-32                          4 bytes
    #       compressed size                 4 bytes
    #       uncompressed size               4 bytes
    #
    # 4.3.9.3 Although not originally assigned a signature, the value
    # 0x08074b50 has commonly been adopted as a signature value

    private def write_footer(
      io      : IO,
      crc     : UInt32,
      src_len : UInt32,
      dst_len : UInt32,
    ) : UInt32
      # write magic (u32)
      MAGIC[:file_footer].to_u32.to_io(io, LE)

      # write crc (u32), compressed size (u32), and full size (u32)
      crc.to_u32.to_io(io, LE)
      dst_len.to_u32.to_io(io, LE)
      src_len.to_u32.to_io(io, LE)

      # return number of bytes written
      16_u32
    end

    #
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

    # TODO: version made by, if unspecified
    CENTRAL_VERSION_MADE_BY = 0_u32

    def write_central(
      io      : IO,
      version : UInt32 = CENTRAL_VERSION_MADE_BY
    ) : UInt32
      MAGIC[:cdr_header].to_u32.to_io(io, LE)
      version.to_u16.to_io(io, LE)
      VERSION_NEEDED.to_u16.to_io(io, LE)
      GENERAL_FLAGS.to_u16.to_io(io, LE)
      @method.to_u16.to_io(io, LE)

      # write time
      write_time(io, @time)

      @crc.to_u32.to_io(io, LE)
      @dst_len.to_u32.to_io(io, LE)
      @src_len.to_u32.to_io(io, LE)

      # get path length and write it
      path_len = @path.bytesize
      path_len.to_u16.to_io(io, LE)

      # write extras field length (u16)
      extras_len = 0_u32
      extras_len.to_u16.to_io(io, LE)

      # write comment field length (u16)
      comment_len = @comment.bytesize
      comment_len.to_u16.to_io(io, LE)

      # write disk number
      0_u32.to_u16.to_io(io, LE)

      # write file attributes (internal, external)
      # TODO
      0_u32.to_u16.to_io(io, LE)
      0_u32.to_u32.to_io(io, LE)

      # write local header offset
      @pos.to_u32.to_io(io, LE)

      # write path field
      @path.to_s(io)

      # write extra fields
      # TODO: implement this

      # write comment
      @comment.to_s(io)

      # return number of bytes written
      46_u32 + path_len + extras_len + comment_len
    end
  end

  class Writer
    getter? :closed

    def initialize(
      @io       : IO,
      @pos      : UInt32 = 0,
      @comment  : String = "",
      @version  : UInt32 = 0,
    )
      @entries = [] of WriterEntry
      @closed = false
      @src_pos = @pos
    end

    private def assert_open
      raise Error.new("already closed") if closed?
    end

    def bytes_written : UInt32
      # return total number of bytes written
      @src_pos - @pos
    end

    def close
      assert_open

      # cache cdr position
      cdr_pos = @pos

      @entries.each do |entry|
        @pos += entry.write_central(@io)
      end

      # write zip footer
      @pos += write_footer(cdr_pos, @pos - cdr_pos)

      # flag as closed
      @closed = true

      # return total number of bytes written
      bytes_written
    end

    def add(
      path    : String,
      io      : IO,
      method  : CompressionMethod = CompressionMethod::DEFLATE,
      time    : Time = Time.now,
      comment : String = "",
    ) : UInt32
      # make sure writer is still open
      assert_open

      # create entry
      entry = WriterEntry.new(
        pos:      @pos,
        path:     path,
        io:       io,
        method:   method,
        time:     time,
        comment:  comment,
      )

      # add to list of entries
      @entries << entry

      # cache offset
      src_pos = @pos

      # write entry, update offset
      @pos += entry.to_s(@io)

      # return number of bytes written
      @pos - src_pos
    end

    def add(
      path    : String,
      data    : String | Bytes,
      method  : CompressionMethod = CompressionMethod::DEFLATE,
      time    : Time = Time.now,
      comment : String = "",
    ) : UInt32
      add(path, MemoryIO.new(data), method, time, comment)
    end

    def add_file(
      path      : String,
      file_path : String,
      method    : CompressionMethod = CompressionMethod::DEFLATE,
      time      : Time = Time.now,
      comment   : String = "",
    ) : UInt32
      File.open(file_path, "rb") do |io|
        add(path, io, method, time, comment)
      end
    end

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

    private def write_footer(
      cdr_pos : UInt32,
      cdr_len : UInt32,
    ) : UInt32
      # write magic (u32)
      MAGIC[:cdr_footer].to_io(@io, LE)

      # write disk num (u16) and footer start disk (u16)
      0_u32.to_u16.to_io(@io, LE)
      0_u32.to_u16.to_io(@io, LE)

      # write num entries (u16) and total entries (u16)
      num_entries = @entries.size
      num_entries.to_u16.to_io(@io, LE)
      num_entries.to_u16.to_io(@io, LE)

      # write cdr offset (u32) and cdr length (u32)
      cdr_len.to_io(@io, LE)
      cdr_pos.to_io(@io, LE)

      # get comment length (u16)
      comment_len = @comment.bytesize

      # write comment length (u16) and comment
      comment_len.to_u16.to_io(@io, LE)
      @comment.to_s(@io)

      # return number of bytes written
      22_u32 + comment_len
    end
  end

  def self.write(
    io      : IO,
    pos     : UInt32 = 0_u32,
    comment : String = "",
    version : UInt32 = 0_u32,
    &cb     : Writer -> \
  ) : UInt32
    r = 0_u32

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

  def self.write(
    path    : String,
    pos     : UInt32 = 0_u32,
    comment : String = "",
    version : UInt32 = 0_u32,
    &cb     : Writer -> \
  ) : UInt32
    File.open(path, "wb") do |io|
      write(io, pos, comment, version, &cb)
    end
  end

  # alias Source = IO::FileDescriptor | MemoryIO

  class Source
    include IO

    def initialize(@io : IO::FileDescriptor | MemoryIO)
    end

    delegate read, to: @io
    delegate write, to: @io
    forward_missing_to @io
  end

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

  class Entry
    getter :version, :version_needed, :flags, :method, :datetime, :crc,
           :compressed_size, :uncompressed_size, :path, :extras,
           :comment, :internal_attr, :external_attr, :pos

    def initialize(io)
      # allocate slice for data
      mem = Bytes.new(46)

      # read entry
      if ((len = io.read(mem)) != 46)
        raise Error.new("couldn't read full CDR entry (#{len} != 46)")
      end

      # create memory io for slice
      mem_io = MemoryIO.new(mem, false)

      magic = UInt32.from_io(mem_io, LE)
      if magic != MAGIC[:cdr_header]
        raise Error.new("invalid CDR header magic")
      end

      # read versions
      @version = UInt16.from_io(mem_io, LE).as(UInt16)
      @version_needed = UInt16.from_io(mem_io, LE).as(UInt16)

      # TODO: check versions

      # read flags, method, and date
      @flags = UInt16.from_io(mem_io, LE).as(UInt16)
      @method = UInt16.from_io(mem_io, LE).as(UInt16)
      @datetime = UInt32.from_io(mem_io, LE).as(UInt32)

      @crc = UInt32.from_io(mem_io, LE).as(UInt32)
      @compressed_size = UInt32.from_io(mem_io, LE).as(UInt32)
      @uncompressed_size = UInt32.from_io(mem_io, LE).as(UInt32)

      # read lengths
      @path_len = UInt16.from_io(mem_io, LE).not_nil!.as(UInt16)
      @extras_len = UInt16.from_io(mem_io, LE).as(UInt16)
      @comment_len = UInt16.from_io(mem_io, LE).as(UInt16)

      @internal_attr = UInt16.from_io(mem_io, LE).as(UInt16)
      @external_attr = UInt32.from_io(mem_io, LE).as(UInt32)
      @pos = UInt32.from_io(mem_io, LE).as(UInt32)

      # close memory io
      mem_io.close

      # read path
      @path = if @path_len > 0
        buf = Bytes.new(@path_len)

        if io.read(buf) != @path_len
          raise Error.new("couldn't read CDR entry name")
        end

        # TODO: handle encoding
        String.new(buf)
      else
        ""
      end

      # read extras
      @extras = if @extras_len > 0
        buf = Bytes.new(@extras_len)

        if io.read(buf) != @extras_len
          raise Error.new("couldn't read CDR entry extras")
        end

        # TODO: decode extras?
        buf
      else
        # TODO
        Bytes.new(0)
      end

      # read comment
      @comment = if @comment_len > 0
        buf = Bytes.new(@comment_len)
        if io.read(buf) != @comment_len
          raise Error.new("couldn't read CDR entry comment")
        end

        # TODO: handle encoding
        String.new(buf)
      else
        ""
      end
    end
  end

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

  class Archive
    getter :entries

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
      if ((len = @io.read(mem)) < mem.size)
        raise Error.new("couldn't read zip footer")
      end

      # create memory io for slice
      mem_io = MemoryIO.new(mem, false)

      # read disk numbers
      @disk_num = mem_io.read_bytes(UInt16, LE).as(UInt16)
      @cdr_disk = mem_io.read_bytes(UInt16, LE).as(UInt16)

      # check disk numbers
      if @disk_num != @cdr_disk
        raise Error.new("multi-disk archives not supported")
      end

      # read entry counts
      @num_disk_entries = mem_io.read_bytes(UInt16, LE).as(UInt16)
      @num_entries = mem_io.read_bytes(UInt16, LE).not_nil!.as(UInt16)

      # check entry counts
      if @num_disk_entries != @num_entries
        raise Error.new("multi-disk archives not supported")
      end

      # read cdr position and length
      @cdr_len = mem_io.read_bytes(UInt32, LE).not_nil!.as(UInt32)
      @cdr_pos = mem_io.read_bytes(UInt32, LE).not_nil!.as(UInt32)

      # check cdr position
      if @cdr_pos.not_nil! + @cdr_len.not_nil! >= end_pos
        raise Error.new("invalid CDR offset: #{@cdr_pos}")
      end

      # read comment length and comment body
      @comment_len = mem_io.read_bytes(UInt16, LE).not_nil!.as(UInt16)
      @comment = if @comment_len.not_nil! > 0
        # allocate space for comment
        slice = Bytes.new(@comment_len.not_nil!)

        # seek to comment position
        @io.pos = footer_pos + 22

        # read comment data
        if ((len = @io.read(slice)) != @comment_len)
          raise Error.new("archive comment read truncated")
        end

        # FIXME: shouldn't assume UTF-8 here
        String.new(slice, "UTF-8")
      else
        ""
      end

      # close memory io
      mem_io.close

      # read entries
      @entries = [] of Entry
      read_entries(@entries, @io, @cdr_pos, @cdr_len, @num_entries)
    end

    private def read_entries(
      entries     : Array(Entry),
      io          : Source,
      cdr_pos     : UInt32,
      cdr_len     : UInt32,
      num_entries : UInt16,
    )
      # get end position
      end_cdr_pos = cdr_pos + cdr_len

      # seek to start of entries
      io.pos = cdr_pos

      # read entries
      num_entries.times do
        # create new entry
        entries << Entry.new(io)

        # check position
        if io.pos > end_cdr_pos
          raise Error.new("read past CDR")
        end
      end
    end

    private def find_footer_and_eof(io : Source)
      # seek to end of file
      io.seek(0, IO::Seek::End)
      end_pos = io.pos

      if end_pos < 22
        raise Error.new("too small for end of central directory")
      end

      curr_pos = end_pos - 22
      while curr_pos >= 0
        # seek to current position
        io.pos = curr_pos

        # read what might be the end_cdr magic
        maybe_end_magic = UInt32.from_io(io, LE)

        if maybe_end_magic == MAGIC[:cdr_footer]
          # jump to archive commment len (maybe)
          maybe_comment_len_pos = curr_pos + 20
          io.pos = maybe_comment_len_pos

          # get archive commment len (maybe)
          maybe_comment_len = UInt16.from_io(io, LE)

          if curr_pos + 22 + maybe_comment_len == end_pos
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
  end

  class Reader
    getter? :closed, :sync_close
    getter :zip

    def initialize(
      @io         : Source,
      @pos        : UInt32 = 0_u32,
      @sync_close : Bool = false,
    )
      @closed = false
      @zip = Archive.new(@io)
    end

    private def assert_open
      raise Error.new("already closed") if closed?
    end

    def close
      assert_open

      @io.close if @sync_close
      @closed = true
    end
  end

  def self.read(
    io          : IO,
    pos         : UInt32 = 0_u32,
    sync_close  : Bool = false,
    &cb         : Archive -> \
  )
    begin
      r = Reader.new(Source.new(io), pos, sync_close)
      cb.call(r.zip)
    ensure
      if r
        r.close unless r.closed?
      end
    end

    nil
  end

  def self.read(
    slice : Bytes,
    &cb   : Archive -> \
  )
    src = Source.new(MemoryIO.new(slice, false))
    read(src, 0_u32, false, &cb)
  end

  def self.read(
    path : String,
    &cb  : Archive -> \
  )
    File.open(path, "rb") do |io|
      read(io, 0_u32, true, &cb)
    end
  end
end
