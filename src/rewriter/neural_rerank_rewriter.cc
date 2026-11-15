// Neural reranking rewriter. See neural_rerank_rewriter.h.

// Socket headers first: on Windows, winsock2.h must come before windows.h.
#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
#else  // _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#endif  // _WIN32

#include "rewriter/neural_rerank_rewriter.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "base/util.h"
#include "converter/candidate.h"
#include "converter/segments.h"
#include "protocol/commands.pb.h"
#include "request/conversion_request.h"

namespace mozc {
namespace {

constexpr uint16_t kDefaultPort = 47801;
constexpr int kDefaultTimeoutMs = 20;
constexpr int kDefaultBackoffMs = 3000;
constexpr size_t kDefaultTopN = 10;
constexpr size_t kDefaultContextChars = 30;
constexpr size_t kMaxResponseBytes = 4096;

int64_t NowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

std::optional<int> GetEnvInt(const char* name) {
  std::string value;
#ifdef _WIN32
  char buf[64];
  const DWORD n = ::GetEnvironmentVariableA(name, buf, sizeof(buf));
  if (n == 0 || n >= sizeof(buf)) {
    return std::nullopt;
  }
  value.assign(buf, n);
#else   // _WIN32
  const char* v = std::getenv(name);
  if (v == nullptr) {
    return std::nullopt;
  }
  value = v;
#endif  // _WIN32
  int result = 0;
  if (!absl::SimpleAtoi(value, &result)) {
    return std::nullopt;
  }
  return result;
}

void AppendJsonString(absl::string_view s, std::string* out) {
  static constexpr char kHex[] = "0123456789abcdef";
  out->push_back('"');
  for (const char ch : s) {
    const unsigned char c = static_cast<unsigned char>(ch);
    switch (c) {
      case '"':
        out->append("\\\"");
        break;
      case '\\':
        out->append("\\\\");
        break;
      case '\n':
        out->append("\\n");
        break;
      case '\r':
        out->append("\\r");
        break;
      case '\t':
        out->append("\\t");
        break;
      default:
        if (c < 0x20) {
          out->append("\\u00");
          out->push_back(kHex[c >> 4]);
          out->push_back(kHex[c & 0xf]);
        } else {
          out->push_back(ch);  // UTF-8 bytes pass through.
        }
    }
  }
  out->push_back('"');
}

// ---------------------------------------------------------------- sockets
#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
void CloseSocket(SocketHandle s) { ::closesocket(s); }
bool InitSockets() {
  static std::once_flag once;
  static bool ok = false;
  std::call_once(once, [] {
    WSADATA data;
    ok = (::WSAStartup(MAKEWORD(2, 2), &data) == 0);
  });
  return ok;
}
bool SetNonBlocking(SocketHandle s) {
  u_long mode = 1;
  return ::ioctlsocket(s, FIONBIO, &mode) == 0;
}
bool ConnectInProgress() {
  const int e = ::WSAGetLastError();
  return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
}
bool WouldBlock() { return ::WSAGetLastError() == WSAEWOULDBLOCK; }
// Waits until |s| is readable (or writable). Returns false on timeout/error.
bool WaitFor(SocketHandle s, bool for_write, int timeout_ms) {
  if (timeout_ms <= 0) {
    return false;
  }
  WSAPOLLFD pfd = {};
  pfd.fd = s;
  pfd.events = for_write ? POLLWRNORM : POLLRDNORM;
  const int r = ::WSAPoll(&pfd, 1, timeout_ms);
  return r > 0 && (pfd.revents & (for_write ? POLLWRNORM : POLLRDNORM)) &&
         !(pfd.revents & POLLNVAL);
}
#else   // _WIN32
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
void CloseSocket(SocketHandle s) { ::close(s); }
bool InitSockets() { return true; }
bool SetNonBlocking(SocketHandle s) {
  const int flags = ::fcntl(s, F_GETFL, 0);
  return flags >= 0 && ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
}
bool ConnectInProgress() { return errno == EINPROGRESS; }
bool WouldBlock() { return errno == EAGAIN || errno == EWOULDBLOCK; }
bool WaitFor(SocketHandle s, bool for_write, int timeout_ms) {
  if (timeout_ms <= 0) {
    return false;
  }
  pollfd pfd = {};
  pfd.fd = s;
  pfd.events = for_write ? POLLOUT : POLLIN;
  const int r = ::poll(&pfd, 1, timeout_ms);
  return r > 0 && (pfd.revents & (for_write ? POLLOUT : POLLIN));
}
#endif  // _WIN32

class ScopedSocket {
 public:
  explicit ScopedSocket(SocketHandle s) : s_(s) {}
  ~ScopedSocket() {
    if (s_ != kInvalidSocket) {
      CloseSocket(s_);
    }
  }
  ScopedSocket(const ScopedSocket&) = delete;
  ScopedSocket& operator=(const ScopedSocket&) = delete;
  SocketHandle get() const { return s_; }

 private:
  SocketHandle s_;
};

#ifdef _WIN32
constexpr int kSendFlags = 0;
#elif defined(MSG_NOSIGNAL)
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

// Sends |request| and reads one line, all within |deadline_ms| (monotonic).
std::optional<std::string> Exchange(uint16_t port, const std::string& request,
                                    int64_t deadline_ms) {
  if (!InitSockets()) {
    return std::nullopt;
  }
  ScopedSocket sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (sock.get() == kInvalidSocket || !SetNonBlocking(sock.get())) {
    return std::nullopt;
  }
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only.
  if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr),
                sizeof(addr)) != 0) {
    if (!ConnectInProgress()) {
      return std::nullopt;
    }
    if (!WaitFor(sock.get(), true, static_cast<int>(deadline_ms - NowMs()))) {
      return std::nullopt;
    }
    int err = 0;
    socklen_t len = sizeof(err);
    if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR,
                     reinterpret_cast<char*>(&err), &len) != 0 ||
        err != 0) {
      return std::nullopt;
    }
  }

  size_t sent = 0;
  while (sent < request.size()) {
    const int n = static_cast<int>(::send(sock.get(), request.data() + sent,
                                          static_cast<int>(request.size() - sent),
                                          kSendFlags));
    if (n > 0) {
      sent += static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && WouldBlock() &&
        WaitFor(sock.get(), true, static_cast<int>(deadline_ms - NowMs()))) {
      continue;
    }
    return std::nullopt;
  }

  std::string response;
  char buf[512];
  while (response.find('\n') == std::string::npos) {
    if (response.size() > kMaxResponseBytes) {
      return std::nullopt;
    }
    if (!WaitFor(sock.get(), false, static_cast<int>(deadline_ms - NowMs()))) {
      return std::nullopt;
    }
    const int n = static_cast<int>(::recv(sock.get(), buf, sizeof(buf), 0));
    if (n > 0) {
      response.append(buf, static_cast<size_t>(n));
      continue;
    }
    if (n < 0 && WouldBlock()) {
      continue;
    }
    return std::nullopt;  // closed or error
  }
  response.resize(response.find('\n'));
  return response;
}

}  // namespace

// ---------------------------------------------------------------- backend
LocalServerRerankBackend::LocalServerRerankBackend(uint16_t port,
                                                   int timeout_ms,
                                                   int backoff_ms)
    : port_(port), timeout_ms_(timeout_ms), backoff_ms_(backoff_ms) {}

std::string LocalServerRerankBackend::BuildRequest(const Query& query) {
  std::string out = "{\"ctx\":";
  AppendJsonString(query.context, &out);
  out.append(",\"key\":");
  AppendJsonString(query.key, &out);
  out.append(",\"cands\":[");
  for (size_t i = 0; i < query.values.size(); ++i) {
    if (i > 0) out.push_back(',');
    AppendJsonString(query.values[i], &out);
  }
  out.append("],\"costs\":[");
  for (size_t i = 0; i < query.costs.size(); ++i) {
    if (i > 0) out.push_back(',');
    out.append(std::to_string(query.costs[i]));
  }
  out.append("]}\n");
  return out;
}

std::optional<std::vector<int>> LocalServerRerankBackend::ParseResponse(
    absl::string_view line, size_t size) {
  if (!line.empty() && line.back() == '\r') {
    line.remove_suffix(1);
  }
  std::vector<absl::string_view> parts =
      absl::StrSplit(line, ' ', absl::SkipEmpty());
  if (parts.empty() || parts[0] != "OK" || parts.size() != size + 1) {
    return std::nullopt;
  }
  std::vector<int> order;
  std::vector<bool> seen(size, false);
  for (size_t i = 1; i < parts.size(); ++i) {
    int v = 0;
    if (!absl::SimpleAtoi(parts[i], &v) || v < 0 ||
        static_cast<size_t>(v) >= size || seen[v]) {
      return std::nullopt;  // must be a permutation
    }
    seen[v] = true;
    order.push_back(v);
  }
  return order;
}

std::optional<std::vector<int>> LocalServerRerankBackend::Rerank(
    const Query& query) const {
  const int64_t now = NowMs();
  if (now < next_try_ms_) {
    return std::nullopt;  // backing off after a recent failure
  }
  std::optional<std::string> line =
      Exchange(port_, BuildRequest(query), now + timeout_ms_);
  std::optional<std::vector<int>> order;
  if (line.has_value()) {
    order = ParseResponse(*line, query.values.size());
  }
  // A malformed answer ("ERR ...") is not a reason to back off, but no answer is.
  next_try_ms_ = line.has_value() ? 0 : NowMs() + backoff_ms_;
  return order;
}

// ---------------------------------------------------------------- rewriter
NeuralRerankRewriter::NeuralRerankRewriter()
    : NeuralRerankRewriter(
          std::make_unique<LocalServerRerankBackend>(
              static_cast<uint16_t>(
                  GetEnvInt("MOZC_RERANK_PORT").value_or(kDefaultPort)),
              GetEnvInt("MOZC_RERANK_TIMEOUT_MS").value_or(kDefaultTimeoutMs),
              kDefaultBackoffMs),
          static_cast<size_t>((std::clamp)(
              GetEnvInt("MOZC_RERANK_TOP_N").value_or(static_cast<int>(kDefaultTopN)),
              2, 50)),
          kDefaultContextChars) {
  enabled_ = GetEnvInt("MOZC_RERANK_DISABLE").value_or(0) == 0;
}

NeuralRerankRewriter::NeuralRerankRewriter(
    std::unique_ptr<RerankBackend> backend, size_t top_n, size_t context_chars)
    : backend_(std::move(backend)),
      top_n_(top_n),
      context_chars_(context_chars) {}

int NeuralRerankRewriter::capability(const ConversionRequest& request) const {
  return enabled_ ? RewriterInterface::CONVERSION
                  : RewriterInterface::NOT_AVAILABLE;
}

std::string NeuralRerankRewriter::LastChars(absl::string_view text,
                                            size_t max_chars) {
  if (max_chars == 0) {
    return "";
  }
  // Walk back over UTF-8 lead bytes.
  size_t count = 0;
  size_t pos = text.size();
  while (pos > 0) {
    --pos;
    if ((static_cast<unsigned char>(text[pos]) & 0xC0) != 0x80) {
      if (++count == max_chars) {
        break;
      }
    }
  }
  return std::string(text.substr(pos));
}

std::string NeuralRerankRewriter::BuildContext(const ConversionRequest& request,
                                               const Segments& segments) const {
  // Text before the cursor from the application, when it is available.
  std::string context(request.context().preceding_text());
  if (context.empty()) {
    // Otherwise, what was committed through Mozc recently.
    for (const Segment& seg : segments.history_segments()) {
      if (seg.candidates_size() > 0) {
        context.append(seg.candidate(0).value);
      }
    }
  }
  return context;
}

bool NeuralRerankRewriter::Rewrite(const ConversionRequest& request,
                                   Segments* segments) const {
  if (!enabled_ || backend_ == nullptr) {
    return false;
  }
  if (request.request_type() != ConversionRequest::CONVERSION ||
      request.incognito_mode()) {
    return false;
  }

  std::string context = BuildContext(request, *segments);
  bool modified = false;
  for (Segment& seg : segments->conversion_segments()) {
    const bool fixed = seg.segment_type() == Segment::FIXED_VALUE ||
                       seg.segment_type() == Segment::SUBMITTED;
    if (!fixed && seg.candidates_size() >= 2) {
      // Positions (within the first top_n_) of ordinary conversion candidates.
      std::vector<int> pos;
      RerankBackend::Query query;
      query.context = LastChars(context, context_chars_);
      query.key = std::string(seg.key());
      const size_t limit = (std::min)(seg.candidates_size(), top_n_);
      for (size_t i = 0; i < limit; ++i) {
        const converter::Candidate& c = seg.candidate(static_cast<int>(i));
        if (c.category != converter::Candidate::DEFAULT_CATEGORY ||
            c.value.empty() || c.key != seg.key() ||
            std::find(query.values.begin(), query.values.end(), c.value) !=
                query.values.end()) {
          continue;
        }
        pos.push_back(static_cast<int>(i));
        query.values.push_back(c.value);
        query.costs.push_back(c.cost);
      }
      if (pos.size() >= 2) {
        std::optional<std::vector<int>> order = backend_->Rerank(query);
        if (order.has_value() && order->size() == pos.size()) {
          std::vector<converter::Candidate> copies;
          copies.reserve(pos.size());
          for (const int p : pos) {
            copies.push_back(seg.candidate(p));
          }
          for (size_t k = 0; k < pos.size(); ++k) {
            if ((*order)[k] != static_cast<int>(k)) {
              *seg.mutable_candidate(pos[k]) = copies[(*order)[k]];
              modified = true;
            }
          }
        }
      }
    }
    // Later segments see the (possibly reordered) first candidate as context.
    if (seg.candidates_size() > 0) {
      context.append(seg.candidate(0).value);
    }
  }
  return modified;
}

}  // namespace mozc
