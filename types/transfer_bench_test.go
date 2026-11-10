package types

// 传输吞吐基准：仅在设置 LOCALCHAT_BENCH=1 时运行，避免拖慢常规测试。
// 用法: LOCALCHAT_BENCH=1 go test ./types -run TestTransferThroughput -v

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/qianliwangyue/LocalCP/pkg/common"
)

func TestTransferThroughput(t *testing.T) {
	if os.Getenv("LOCALCHAT_BENCH") != "1" {
		t.Skip("设置 LOCALCHAT_BENCH=1 才运行吞吐基准")
	}

	const portBase = 4600
	// 文件大小可用 LOCALCHAT_BENCH_MB 覆盖：短测默认 20MB，
	// 要看分块/加密的真实开销时放大到 400MB，避免固定开销淹没结果
	sizeMB := 20
	if v := os.Getenv("LOCALCHAT_BENCH_MB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sizeMB = n
		}
	}

	os.RemoveAll("received_files")
	defer os.RemoveAll("received_files")

	a := NewChatClient()
	a.SetName("BenchA")
	a.SetPortBase(portBase)
	b := NewChatClient()
	b.SetName("BenchB")
	b.SetPortBase(portBase)

	var mu sync.Mutex
	received := make(chan struct{}, 1)
	var peersA, peersB []common.Peer
	a.OnPeersChanged = func(p []common.Peer) { mu.Lock(); peersA = p; mu.Unlock() }
	b.OnPeersChanged = func(p []common.Peer) { mu.Lock(); peersB = p; mu.Unlock() }
	b.OnFileOffer = func(from, fromAddr, fileName string, size int64, fileID string) {
		go b.AcceptFile(fileID)
	}
	b.OnTransferEnded = func(sending bool, text string) {
		if !sending {
			mu.Lock()
			select {
			case received <- struct{}{}:
			default:
			}
			mu.Unlock()
		}
	}
	a.Start()
	b.Start()
	defer a.Stop()
	defer b.Stop()

	// 等待互相发现
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := len(peersA) > 0 && len(peersB) > 0
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	var targetIP string
	var targetPort int
	mu.Lock()
	for _, p := range peersA {
		if p.Name == "BenchB" {
			targetIP, targetPort = p.IP, p.Port
		}
	}
	mu.Unlock()
	if targetIP == "" {
		t.Fatal("未发现对端")
	}
	if !a.StartChatWith(targetIP, targetPort) {
		t.Fatal("建立会话失败")
	}
	time.Sleep(500 * time.Millisecond)

	// 生成测试文件
	tmp := t.TempDir()
	src := filepath.Join(tmp, "bench.bin")
	data := make([]byte, sizeMB*1024*1024)
	for i := range data {
		data[i] = byte((i*31 + i/7) % 251)
	}
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatal(err)
	}

	// 连续跑 3 次取中位数，规避单次调度抖动；每轮换一个接收目录，避免同名覆盖
	var samples []time.Duration
	lastDir := ""
	for i := 0; i < 3; i++ {
		lastDir = filepath.Join(tmp, fmt.Sprintf("recv%d", i))
		if err := b.SetFileDataDir(lastDir); err != nil {
			t.Fatalf("设置接收目录失败: %v", err)
		}
		start := time.Now()
		if !a.SendFile(src) {
			t.Fatal("发送失败")
		}
		select {
		case <-received:
		case <-time.After(120 * time.Second):
			t.Fatal("传输超时")
		}
		samples = append(samples, time.Since(start))
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	elapsed := samples[len(samples)/2] // 中位数
	mbps := float64(sizeMB) / elapsed.Seconds()
	t.Logf("吞吐: %.2f MB/s（%.0f Mbps），中位耗时 %v，文件 %d MB（3 次: %v）",
		mbps, mbps*8, elapsed.Round(time.Millisecond), sizeMB, samples)

	// 内容校验：确认优化后传输的数据仍然逐字节一致
	got, err := os.ReadFile(filepath.Join(lastDir, "bench.bin"))
	if err != nil {
		t.Fatalf("读取接收文件失败: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("长度不符: 收到 %d 字节，应为 %d 字节", len(got), len(data))
	}
	sumWant := sha256.Sum256(data)
	sumGot := sha256.Sum256(got)
	if sumWant != sumGot {
		t.Fatal("内容校验失败：接收文件与源文件不一致")
	}
	t.Log("内容校验通过（SHA-256 一致）")
}

// TestTuneTCPWorksOnTLSConn 确认 tuneTCP 能穿过 TLS 包装拿到真实 TCP 连接并完成设置，
// 且设置后链路依然可用（NetConn() 取错对象会让后续所有传输静默失效）。
func TestTuneTCPWorksOnTLSConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, tlsServerConfig())

	done := make(chan error, 1)
	go func() {
		c, err := tlsLn.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		tuneTCP(c)
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			done <- err
			return
		}
		_, err = c.Write(buf)
		done <- err
	}()

	c, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tuneTCP(c)

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("回显内容不符: %q", buf)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestTuneTCPIgnoresNonTCPConn 对非 TCP 连接（如 net.Pipe）必须安静地什么都不做
func TestTuneTCPIgnoresNonTCPConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tuneTCP(a) // 不应 panic
	tuneTCP(nil)
}

// TestFolderThroughput 小文件文件夹传输基准：验证「每文件 100ms 轮询等待」的固定开销
// 用法: LOCALCHAT_BENCH=1 go test ./types -run TestFolderThroughput -v
func TestFolderThroughput(t *testing.T) {
	if os.Getenv("LOCALCHAT_BENCH") != "1" {
		t.Skip("设置 LOCALCHAT_BENCH=1 才运行吞吐基准")
	}

	const portBase = 4700
	const fileCount = 300
	const fileSize = 4 * 1024

	os.RemoveAll("received_files")
	defer os.RemoveAll("received_files")

	a := NewChatClient()
	a.SetName("FolderA")
	a.SetPortBase(portBase)
	b := NewChatClient()
	b.SetName("FolderB")
	b.SetPortBase(portBase)

	var mu sync.Mutex
	var peersA []common.Peer
	done := make(chan struct{}, 1)
	a.OnPeersChanged = func(p []common.Peer) { mu.Lock(); peersA = p; mu.Unlock() }
	b.OnFolderOffer = func(from, fromAddr, folderName string, size int64, fileCount int, folderID string) {
		go b.AcceptFolder(folderID)
	}
	b.OnTransferEnded = func(sending bool, text string) {
		if !sending {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	}
	a.Start()
	b.Start()
	defer a.Stop()
	defer b.Stop()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(peersA)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	var ip string
	var port int
	mu.Lock()
	for _, p := range peersA {
		if p.Name == "FolderB" {
			ip, port = p.IP, p.Port
		}
	}
	mu.Unlock()
	if !a.StartChatWith(ip, port) {
		t.Fatal("建立会话失败")
	}
	time.Sleep(500 * time.Millisecond)

	dir := filepath.Join(t.TempDir(), "many")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, fileSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	for i := 0; i < fileCount; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%03d.dat", i)), payload, 0644); err != nil {
			t.Fatal(err)
		}
	}

	start := time.Now()
	if !a.SendFolder(dir) {
		t.Fatal("发送文件夹失败")
	}
	select {
	case <-done:
	case <-time.After(180 * time.Second):
		t.Fatal("文件夹传输超时")
	}
	elapsed := time.Since(start)
	t.Logf("小文件文件夹: %d 个文件，耗时 %v（平均 %.1f ms/文件）",
		fileCount, elapsed.Round(time.Millisecond), float64(elapsed.Milliseconds())/fileCount)
}
