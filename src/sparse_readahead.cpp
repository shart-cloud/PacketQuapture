#include "sparse_readahead.hpp"

#if defined(__linux__) && !defined(__EMSCRIPTEN__)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#define PACKETQUAPTURE_READAHEAD 1
#endif

namespace packetquapture {

SparseReadahead::SparseReadahead(const std::string &path, uint64_t expected_size) {
#ifdef PACKETQUAPTURE_READAHEAD
	// Non-blocking, so a FIFO swapped in at the path cannot stall the scan; and
	// only a regular file of the size being read, so a replaced file gets no hints.
	descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	struct stat status;
	if (descriptor >= 0 && (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
	                        static_cast<uint64_t>(status.st_size) != expected_size)) {
		::close(descriptor);
		descriptor = -1;
	}
	size = expected_size;
	const long page = ::sysconf(_SC_PAGESIZE);
	page_size = page > 0 ? static_cast<uint64_t>(page) : 4096;
#else
	(void)path;
	(void)expected_size;
#endif
}

SparseReadahead::~SparseReadahead() {
#ifdef PACKETQUAPTURE_READAHEAD
	if (descriptor >= 0) {
		::close(descriptor);
	}
#endif
}

// Whether the page at offset is already in the page cache. A scan that finds
// the far end of its next window cached has, in practice, the window cached:
// the file was read before, or the kernel already read ahead that far. One
// page asks mincore(2) for the least.
bool SparseReadahead::Resident(uint64_t offset) const {
#ifdef PACKETQUAPTURE_READAHEAD
	const uint64_t aligned = offset - offset % page_size;
	void *mapping = ::mmap(nullptr, page_size, PROT_READ, MAP_SHARED, descriptor, static_cast<off_t>(aligned));
	if (mapping == MAP_FAILED) {
		return false;
	}
	unsigned char page = 0;
	const bool resident = ::mincore(mapping, page_size, &page) == 0 && (page & 1U) != 0;
	::munmap(mapping, page_size);
	return resident;
#else
	(void)offset;
	return false;
#endif
}

void SparseReadahead::Ahead(uint64_t position) {
#ifdef PACKETQUAPTURE_READAHEAD
	if (descriptor < 0 || position + LOOKAHEAD / 2 <= hinted_until || position >= size) {
		return;
	}
	if (hinted_until < position) {
		hinted_until = position;
	}
	const uint64_t end = position + LOOKAHEAD < size ? position + LOOKAHEAD : size;
	if (hinted_until >= end) {
		return;
	}
	if (Resident(end - 1)) {
		hinted_until = end;
		return;
	}
	// Advice only: a failure costs the hint, never the scan.
	for (; hinted_until < end; hinted_until += PIECE) {
		(void)::posix_fadvise(descriptor, static_cast<off_t>(hinted_until), static_cast<off_t>(PIECE),
		                      POSIX_FADV_WILLNEED);
	}
#else
	(void)position;
#endif
}

} // namespace packetquapture
