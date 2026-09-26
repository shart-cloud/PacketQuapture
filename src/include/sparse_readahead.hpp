#pragma once

#include <cstdint>
#include <string>

namespace packetquapture {

// Asks the kernel to read ahead through a local file whose records are read
// sparsely: a small header, then a seek past a payload. The seeks stop the
// kernel's own sequential readahead, so on a cold page cache every header
// becomes a separate disk read; hinting the upcoming range restores one
// sequential read. The hint is not a read(2): it moves no bytes into the
// process and changes nothing the reader sees.
//
// Linux only. Elsewhere, or when the path cannot be opened, it does nothing.
// It reopens the path read-only, since DuckDB's FileSystem exposes no
// descriptor or advice call; the page cache is shared per file, so a hint
// through either descriptor serves both.
class SparseReadahead {
public:
	// expected_size is the size of the file being read; a file of another size
	// at the path, or one that is not a regular file, gets no hints.
	SparseReadahead(const std::string &path, uint64_t expected_size);
	~SparseReadahead();
	SparseReadahead(const SparseReadahead &) = delete;
	SparseReadahead &operator=(const SparseReadahead &) = delete;

	// Keeps up to LOOKAHEAD bytes past position hinted, a PIECE at a time,
	// topping up once half of it has been read. Linux caps each hint at the
	// device's readahead window, 128 KiB by default, and silently ignores the
	// rest, so larger hints do nothing more. A window already cached is not
	// hinted.
	void Ahead(uint64_t position);

	static constexpr uint64_t PIECE = 128ULL * 1024ULL;
	static constexpr uint64_t LOOKAHEAD = 4ULL * 1024ULL * 1024ULL;

private:
	bool Resident(uint64_t offset) const;

	int descriptor = -1;
	uint64_t size = 0, page_size = 4096, hinted_until = 0;
};

} // namespace packetquapture
