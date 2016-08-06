require "./zip/*"
require "zlib"

module Zip
  VERSION = "0.1.0"

  LE = IO::ByteFormat::LittleEndian

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
    WEAK_ENCRYPTION
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

  module Util
    def self.write_time(io : IO, time : Time) : UInt64
      # TODO
      0_u32.to_u16.to_io(io, LE)
      0_u32.to_u16.to_io(io, LE)

      # return number of bytes written
      4_u64
    end
  end

  # TODO
  class Reader
    def initialize(path : String)
    end

    def initialize(io : IO)
    end
  end

  module NoneCompressor
    def compress_none(src_io, dst_io)
      crc = 0_u32

      buf = Bytes.new(4096)
      src_len = 0_u64

      while ((len = src_io.read(buf)) > 0)
        # TODO: crc32

        dst_io.write((len < buf.size) ? Bytes.new(buf.to_unsafe, len) : buf)
        src_len += len
      end

      # return results
      { crc, src_len, src_len }
    end
  end

  module DeflateCompressor
    def compress_deflate(src_io, dst_io)
      crc = 0_u32
      src_len = 0_u64
      dst_len = 0_u64

      # create buffer and intermediate memory io
      buf = Bytes.new(4096)
      mem_io = MemoryIO.new(4096)

      Zlib::Deflate.new(
        output:     mem_io,
        sync_close: false,
      ) do |zlib_io|
        while ((len = src_io.read(buf)) > 0)
          # TODO: crc32

          # compress bytes to memory io
          zlib_io.write((len < buf.size) ? Bytes.new(buf.to_unsafe, len) : buf)
          src_len += len

          # write compressed bytes to dst_io
          dst_io.write(Bytes.new(mem_io.buffer, mem_io.pos))
          dst_len += mem_io.pos

          # clear memio
          mem_io.rewind
        end
      end

      # return results
      { crc, src_len, dst_len }
    end
  end

  class WriterEntry
    include NoneCompressor
    include DeflateCompressor

    # TODO version needed to extract and header flags
    # (used for header and central header)
    VERSION_NEEDED = 0_u32
    GENERAL_FLAGS = GeneralFlags.flags(FOOTER, EFS)

    def initialize(
      @pos      : UInt64,
      @path     : String,
      @io       : IO,
      @method   : CompressionMethod = CompressionMethod::DEFLATE,
      @time     : Time = Time.now,
      @comment  : String = "",
    )
      @crc = 0_u32
      @src_len = 0_u64
      @dst_len = 0_u64
    end

    def to_s(dst_io) : UInt64
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

    HEADER_MAGIC = 0x04034b50_u32

    private def write_header(
      io      : IO,
      path    : String,
      method  : CompressionMethod,
      time    : Time,
    ) : UInt64
      # get path length, in bytes
      path_len = path.bytesize

      # check file path
      raise "empty file path" if path_len == 0
      raise "file path too long" if path_len >= UInt16::MAX
      raise "file path contains leading slash" if path[0] == '/'

      # write magic, version needed, flags, and compression method
      HEADER_MAGIC.to_io(io, LE)
      VERSION_NEEDED.to_u16.to_io(io, LE)
      GENERAL_FLAGS.to_u16.to_io(io, LE)
      method.to_u16.to_io(io, LE)

      # write time
      Util.write_time(io, time)

      # crc, compressed size, uncompressed size
      # (these will be populated in the footer)
      0_u32.to_io(io, LE)
      0_u32.to_io(io, LE)
      0_u32.to_io(io, LE)
      path_len.to_u16.to_io(io, LE)

      # write extras field length
      extras_len = 0_u32
      extras_len.to_u16.to_io(io, LE)

      # write path field
      path.to_s(io)

      # write extra fields
      # TODO: implement this

      # return number of bytes written
      30_u64 + path_len + extras_len
    end

    private def write_body(dst_io : IO)
      case @method
      when CompressionMethod::NONE
        compress_none(@io, dst_io)
      when CompressionMethod::DEFLATE
        compress_deflate(@io, dst_io)
      else
        raise "unsupported compression method"
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

    FOOTER_MAGIC = 0x08074b50_u32

    private def write_footer(
      io      : IO,
      crc     : UInt32,
      src_len : UInt64,
      dst_len : UInt64,
    ) : UInt64
      # write footer
      FOOTER_MAGIC.to_io(io, LE)
      crc.to_io(io, LE)
      dst_len.to_io(io, LE)
      src_len.to_io(io, LE)

      # return number of bytes written
      16_u64
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

    CENTRAL_MAGIC = 0x02014b50_u32

    # TODO: version made by, if unspecified
    CENTRAL_VERSION_MADE_BY = 0_u32

    def write_central(
      io      : IO,
      version : UInt32 = CENTRAL_VERSION_MADE_BY
    ) : UInt64
      CENTRAL_MAGIC.to_io(io, LE)
      version.to_u16.to_io(io, LE)
      VERSION_NEEDED.to_u16.to_io(io, LE)
      GENERAL_FLAGS.to_u16.to_io(io, LE)
      @method.to_u16.to_io(io, LE)

      # write time
      Util.write_time(io, @time)

      @crc.to_io(io, LE)
      @dst_len.to_io(io, LE)
      @src_len.to_io(io, LE)

      # get path length and write it
      path_len = @path.bytesize
      path_len.to_u16.to_io(io, LE)

      # write extras field length
      extras_len = 0_u32
      extras_len.to_u16.to_io(io, LE)

      comment_len = @comment.bytesize
      comment_len.to_u16.to_io(io, LE)

      # write disk number
      0_u32.to_u16.to_io(io, LE)

      # write file attributes (internal, external)
      # TODO
      0_u32.to_u16.to_io(io, LE)
      0_u32.to_u16.to_io(io, LE)

      # write local header offset
      @pos.to_u32.to_io(io, LE)

      # write path field
      @path.to_s(io)

      # write extra fields
      # TODO: implement this

      # write comment
      @comment.to_s(io)

      # return number of bytes written
      30_u64 + path_len + extras_len

      # TODO
      0_u64
    end

  end

  class Writer
    def initialize(
      @io       : IO,
      @pos      : UInt64 = 0,
      @comment  : String = "",
      @version  : UInt32 = 0,
    )
      @entries = [] of WriterEntry
      @closed = false
      @src_pos = @pos
    end

    def closed?
      @closed
    end

    private def assert_open
      raise "already closed" if closed?
    end

    def bytes_written : UInt64
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
      write_footer(cdr_pos)

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
    ) : UInt64
      # cache input position
      src_pos = @pos

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

      # write entry, update offset
      @pos += entry.to_s(@io)

      # return number of bytes written
      @pos - src_pos
    end

    # 4.3.16  End of central directory record:
    #
    # end of central dir signature    4 bytes  (0x06054b50)
    # number of this disk             2 bytes
    # number of the disk with the
    # start of the central directory  2 bytes
    # total number of entries in the
    # central directory on this disk  2 bytes
    # total number of entries in
    # the central directory           2 bytes
    # size of the central directory   4 bytes
    # offset of start of central
    # directory with respect to
    # the starting disk number        4 bytes
    # .ZIP file comment length        2 bytes
    # .ZIP file comment       (variable size)

    FOOTER_MAGIC = 0x06054b50_u32

    private def write_footer(cdr_pos : UInt64)
      # write magic (u32), disk num (u16), start footer disk (u16)
      FOOTER_MAGIC.to_io(@io, LE)
      0_u32.to_u16.to_io(@io, LE)
      0_u32.to_u16.to_io(@io, LE)

      # write num entries (u16) / total entries (u16)
      num_entries = @entries.size
      num_entries.to_u16.to_io(@io, LE)
      num_entries.to_u16.to_io(@io, LE)

      # write offset (u32)
      (cdr_pos - @src_pos).to_u32.to_io(@io, LE)
      cdr_pos.to_io(@io, LE)

      # write comment length (u16) and comment
      @comment.bytesize.to_u16.to_io(@io, LE)
      @comment.to_s(@io)
    end
  end

  def self.write(
    io      : IO,
    pos     : UInt64 = 0_u64,
    comment : String = "",
    version : UInt32 = 0_u32,
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

  def self.write(
    path    : String,
    pos     : UInt64 = 0_u64,
    comment : String = "",
    version : UInt32 = 0_u32,
    &cb     : Writer -> \
  ) : UInt64
    File.open(path, "wb") do |io|
      write(io, pos, comment, version, &cb)
    end
  end
end
