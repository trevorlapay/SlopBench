// A compact, read-only index of the artifact names in one spool directory.
//
// The thumbnail workers scan the spool tens of thousands of times an hour and
// only ever read the names, so the names are held in one contiguous buffer and
// handed out as views into it rather than as separate allocations.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace slopshop::media {

// A view handed out by CatalogView refers to storage the CatalogView owns and
// is valid for as long as that CatalogView is alive.
class CatalogView {
 public:
  CatalogView() = default;

  CatalogView(const CatalogView&) = delete;
  CatalogView& operator=(const CatalogView&) = delete;
  CatalogView(CatalogView&&) = delete;
  CatalogView& operator=(CatalogView&&) = delete;

  ~CatalogView() = default;

  // Builds the index from a list of names. Any previous contents are dropped.
  void Build(const std::vector<std::string>& names) {
    buffer_.clear();
    entries_.clear();

    std::size_t total = 0;
    for (const std::string& name : names) {
      total += name.size();
    }

    buffer_.reserve(total);
    entries_.reserve(names.size());

    for (const std::string& name : names) {
      const std::size_t offset = buffer_.size();
      buffer_.append(name);
      entries_.push_back(Entry{offset, name.size()});
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

  // Returns the name at `index`.
  [[nodiscard]] std::string_view Name(std::size_t index) const {
    if (index >= entries_.size()) {
      throw std::out_of_range("catalog index is out of range");
    }
    const Entry& entry = entries_[index];
    return std::string_view(buffer_).substr(entry.offset, entry.length);
  }

  // Returns the index of `name`, or size() when it is absent.
  [[nodiscard]] std::size_t Find(std::string_view name) const {
    for (std::size_t index = 0; index < entries_.size(); ++index) {
      if (Name(index) == name) {
        return index;
      }
    }
    return entries_.size();
  }

  // Copies out every name that starts with `prefix`.
  [[nodiscard]] std::vector<std::string> WithPrefix(std::string_view prefix) const {
    std::vector<std::string> matches;
    for (std::size_t index = 0; index < entries_.size(); ++index) {
      const std::string_view candidate = Name(index);
      if (candidate.size() >= prefix.size() &&
          candidate.compare(0, prefix.size(), prefix) == 0) {
        matches.emplace_back(candidate);
      }
    }
    return matches;
  }

  // Total bytes held, for the metrics endpoint.
  [[nodiscard]] std::size_t BytesHeld() const noexcept {
    return buffer_.size() + entries_.size() * sizeof(Entry);
  }

 private:
  struct Entry {
    std::size_t offset;
    std::size_t length;
  };

  std::string buffer_;
  std::vector<Entry> entries_;
};

}  // namespace slopshop::media
