// Neural reranking rewriter (personal experiment, not part of upstream Mozc).
//
// Sends the top candidates of each conversion segment, together with the
// preceding text, to a local reranking server (127.0.0.1 only) and reorders
// them by the returned order. The server scores how natural each candidate is
// after the preceding text with a small character-level GRU language model.
//
// Safety rules:
//  - Only CONVERSION requests (not prediction / suggestion).
//  - Skipped in incognito mode and for segments the user has fixed.
//  - If the server is not running, does not answer within the time budget, or
//    returns something unexpected, the original Mozc order is kept. After a
//    failure the server is not contacted again for a short back-off period, so
//    a stopped server costs at most one time budget every few seconds.
//
// The exchange is behind a small interface (RerankBackend) so that the
// network backend can later be replaced by an in-process ONNX Runtime backend.

#ifndef MOZC_REWRITER_NEURAL_RERANK_REWRITER_H_
#define MOZC_REWRITER_NEURAL_RERANK_REWRITER_H_

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "converter/segments.h"
#include "request/conversion_request.h"
#include "rewriter/rewriter_interface.h"

namespace mozc {

class RerankBackend {
 public:
  struct Query {
    std::string context;              // preceding text (UTF-8)
    std::string key;                  // reading of the segment
    std::vector<std::string> values;  // candidates in Mozc order
    std::vector<int32_t> costs;       // Mozc costs, same length as values
    // Client-side statistics of earlier exchanges (sent for diagnosis).
    int stat_count = 0;
    int stat_timeouts = 0;
    int stat_last_ms = 0;
    int stat_max_ms = 0;
    int stat_connects = 0;
  };

  virtual ~RerankBackend() = default;

  // Returns a permutation of [0, values.size()) or std::nullopt on failure.
  virtual std::optional<std::vector<int>> Rerank(const Query& query) const = 0;
};

// Talks to src/rerank_server.py of the IME project over a TCP socket bound to
// 127.0.0.1. One short connection per query.
class LocalServerRerankBackend : public RerankBackend {
 public:
  LocalServerRerankBackend(uint16_t port, int timeout_ms, int backoff_ms);
  ~LocalServerRerankBackend() override;
  std::optional<std::vector<int>> Rerank(const Query& query) const override;

  // Exposed for tests.
  static std::string BuildRequest(const Query& query);
  static std::optional<std::vector<int>> ParseResponse(absl::string_view line,
                                                       size_t size);

 private:
  uint16_t port_;
  int timeout_ms_;
  int backoff_ms_;
  struct Connection;
  std::optional<std::string> Exchange(const std::string& request,
                                      int64_t deadline_ms) const;

  mutable std::mutex mutex_;
  std::unique_ptr<Connection> conn_;
  mutable int64_t next_try_ms_ = 0;  // monotonic ms; 0 = try now
  mutable int stat_connects_ = 0;
  mutable int stat_count_ = 0;
  mutable int stat_timeouts_ = 0;
  mutable int stat_last_ms_ = 0;
  mutable int stat_max_ms_ = 0;
};

class NeuralRerankRewriter : public RewriterInterface {
 public:
  // Default: port 47801 (env MOZC_RERANK_PORT), 20 ms (env MOZC_RERANK_TIMEOUT_MS),
  // top 10 candidates (env MOZC_RERANK_TOP_N), context 30 chars.
  // Set env MOZC_RERANK_DISABLE=1 to turn the rewriter off.
  NeuralRerankRewriter();
  explicit NeuralRerankRewriter(std::unique_ptr<RerankBackend> backend,
                                size_t top_n = 10, size_t context_chars = 30);

  int capability(const ConversionRequest& request) const override;
  bool Rewrite(const ConversionRequest& request,
               Segments* segments) const override;

  // Exposed for tests: last |max_chars| Unicode characters of |text|.
  static std::string LastChars(absl::string_view text, size_t max_chars);
  // Exposed for tests: |preceding| without the trailing composition |key|.
  static std::string StripComposition(absl::string_view preceding,
                                      absl::string_view key);

 private:
  std::string BuildContext(const ConversionRequest& request,
                           const Segments& segments) const;

  std::unique_ptr<RerankBackend> backend_;
  size_t top_n_;
  size_t context_chars_;
  bool enabled_ = true;
};

}  // namespace mozc

#endif  // MOZC_REWRITER_NEURAL_RERANK_REWRITER_H_
