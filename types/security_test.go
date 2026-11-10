package types

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qianliwangyue/LocalCP/pkg/common"
)

// ---------- 证书/配置目录规范化 ----------

// TestDefaultConfigDirUsesSystemLocation 默认（无环境变量、无便携标记）时，
// 证书根目录必须落在系统标准用户配置目录，且绝不位于当前工作目录下。
func TestDefaultConfigDirUsesSystemLocation(t *testing.T) {
	t.Setenv(envConfigDir, "") // 置空等价于未设置

	d, err := configDir()
	if err != nil {
		t.Fatalf("configDir 失败: %v", err)
	}
	uc, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("本机无法获取用户配置目录，跳过: %v", err)
	}
	want := filepath.Join(uc, appDirName)
	if d != want {
		t.Fatalf("configDir() = %q, 期望系统标准位置 %q", d, want)
	}

	// 必须与当前工作目录无关（旧实现用 cwd 下的 .tls，导致同机多套身份）
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(cwd, d); err == nil &&
		rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("证书目录 %q 竟位于当前工作目录 %q 之下，应改为系统标准位置", d, cwd)
	}
}

// TestConfigDirIndependentOfCwd 切换工作目录后，证书目录必须保持不变
// （这是「同一台机器只有一个设备身份」的前提）。
func TestConfigDirIndependentOfCwd(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envConfigDir, root)

	first, err := configDir()
	if err != nil {
		t.Fatal(err)
	}

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	second, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("切换工作目录后证书目录变化: %q -> %q", first, second)
	}
}

// TestCertPersistedAndStable 证书应持久化到配置目录的 tls/ 下，
// 重复加载得到同一指纹（重启、升级后身份不变）。
func TestCertPersistedAndStable(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envConfigDir, root)

	info1, err := LocalCertInfo()
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	certPath := filepath.Join(root, "tls", "host.crt")
	keyPath := filepath.Join(root, "tls", "host.key")
	if info1.Path != certPath {
		t.Fatalf("证书路径 = %q, 期望 %q", info1.Path, certPath)
	}
	for _, p := range []string{certPath, keyPath} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("证书文件应已落盘 %q: %v", p, err)
		}
		if st.Size() == 0 {
			t.Fatalf("证书文件为空: %q", p)
		}
	}

	// 指纹格式：SHA-256 → 32 字节 → "AA:BB:..." 共 95 字符
	if len(info1.Fingerprint) != 95 || strings.Count(info1.Fingerprint, ":") != 31 {
		t.Fatalf("指纹格式异常: %q", info1.Fingerprint)
	}
	if info1.Fingerprint != strings.ToUpper(info1.Fingerprint) {
		t.Fatalf("指纹应为大写十六进制: %q", info1.Fingerprint)
	}

	// 再次加载必须是同一身份
	info2, err := LocalCertInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info1.Fingerprint != info2.Fingerprint {
		t.Fatalf("重复加载指纹变化: %q != %q", info1.Fingerprint, info2.Fingerprint)
	}
}

// ---------- sanitizeFileName ----------

func TestSanitizeFileName(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		isErr bool
	}{
		{"正常文件.txt", "正常文件.txt", false},
		{`..\..\evil.exe`, "evil.exe", false},          // 目录成分被剥离
		{"../../evil.sh", "evil.sh", false},            // 目录成分被剥离
		{"C:/Users/x/secret.doc", "secret.doc", false}, // 盘符路径只保留文件名
		{"a*b?c<d>e|f.txt", "a_b_c_d_e_f.txt", false},  // Windows 非法字符替换
		{"trailing dots... ", "trailing dots", false},  // 结尾点/空格去除
		{"", "", true},
		{"..", "", true},
		{".", "", true},
		{"CON", "", true},      // Windows 保留设备名
		{"com1.txt", "", true}, // 保留设备名（忽略大小写，含扩展名形式）
	}
	for _, tc := range cases {
		got, err := sanitizeFileName(tc.in)
		if tc.isErr {
			if err == nil {
				t.Errorf("sanitizeFileName(%q) 应返回错误，实际得到 %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("sanitizeFileName(%q) 意外出错: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("sanitizeFileName(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}
}

// ---------- sanitizeRelativePath ----------

func TestSanitizeRelativePath(t *testing.T) {
	// 合法：普通子目录结构
	got, err := sanitizeRelativePath("子目录/照片/图1.png")
	if err != nil || got != "子目录/照片/图1.png" {
		t.Fatalf("合法相对路径被误拒: %q, err=%v", got, err)
	}
	got, err = sanitizeRelativePath(`docs\2026\report.docx`)
	if err != nil || got != "docs/2026/report.docx" {
		t.Fatalf("Windows反斜杠路径未正确归一: %q, err=%v", got, err)
	}

	// 非法：各种路径遍历变体
	bad := []string{
		"../../../etc/passwd",
		`..\..\..\Windows\system32\evil.dll`,
		"C:/Windows/evil",
		`C:\evil.exe`,
		"\\\\server\\share\\x", // UNC
		"//server/share/x",     // UNC（正斜杠形态）
		"a/../..",
		"..",
		"./..",
		"",
		"   ",
	}
	for _, b := range bad {
		if got, err := sanitizeRelativePath(b); err == nil {
			t.Errorf("sanitizeRelativePath(%q) 应拒绝，实际放行为 %q", b, got)
		}
	}
}

// ---------- safeJoinUnder ----------

func TestSafeJoinUnder(t *testing.T) {
	base := t.TempDir()

	// 合法：落在 base 内的子目录文件
	p, err := safeJoinUnder(base, "sub/dir/file.txt")
	if err != nil {
		t.Fatalf("safeJoinUnder 意外出错: %v", err)
	}
	if want := filepath.Join(base, "sub", "dir", "file.txt"); p != want {
		t.Fatalf("safeJoinUnder = %q, 期望 %q", p, want)
	}

	// 非法：任何试图逃出 base 的路径
	attacks := []string{
		"../../../evil.txt",
		`..\..\evil.exe`,
		"sub/../../../evil",
		"C:/evil",
	}
	for _, a := range attacks {
		if p, err := safeJoinUnder(base, a); err == nil {
			t.Errorf("safeJoinUnder(%q) 应拒绝，实际放行 %q", a, p)
		}
	}
}

// ---------- TLS 加密传输端到端 ----------

// TestTLSChannelEndToEnd 验证改造后所有 TCP 通道均为 TLS：
// 1) 裸 TCP 连服务端会握手失败（无法再用明文通道）；
// 2) 用 TLS 客户端连接后可正常完成协议消息收发。
func TestTLSChannelEndToEnd(t *testing.T) {
	t.Setenv(envConfigDir, t.TempDir()) // 证书写临时目录，不污染用户配置
	os.RemoveAll("received_files")
	t.Cleanup(func() { os.RemoveAll("received_files") })

	c := NewChatClient()
	c.SetName("TLSTest")
	c.SetPortBase(6400)
	c.OnLog = func(string) {}
	c.Start()
	t.Cleanup(c.Stop)
	waitFor(t, 10*time.Second, func() bool { return c.TCPPort() != 0 }, "TCP监听应就绪")

	addr := fmt.Sprintf("127.0.0.1:%d", c.TCPPort())

	// 1) 明文直连必须被 TLS 层拦截
	plain, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("裸TCP拨号失败: %v", err)
	}
	_, _ = plain.Write([]byte(`{"type":"chat","port":1,"content":"plaintext"}` + "\n"))
	_ = plain.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	if _, err := plain.Read(buf); err == nil {
		t.Fatal("明文连接不应被服务端接受，却仍可读取")
	}
	plain.Close()

	// 2) TLS 连接应正常工作
	got := make(chan string, 1)
	c.OnChatMessage = func(from, content string) { got <- content }

	tconn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsClientConfig())
	if err != nil {
		t.Fatalf("TLS拨号失败: %v", err)
	}
	defer tconn.Close()

	// 用与本机监听端口不同的假端口，避免触发自连保护
	hello := common.Message{Type: common.MsgTypeChat, From: "Peer", Port: 65111, Content: "TLS你好"}
	data, _ := json.Marshal(hello)
	if _, err := tconn.Write(append(data, '\n')); err != nil {
		t.Fatalf("TLS发送失败: %v", err)
	}
	select {
	case content := <-got:
		if content != "TLS你好" {
			t.Fatalf("收到的消息不符: %q", content)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS通道未收到聊天消息")
	}

	// 3) 对端证书应为自签证书（CN=localcp.local），证明链路确已加密
	state := tconn.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatal("TLS握手应已完成")
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("服务端应提供证书")
	}
	if cn := state.PeerCertificates[0].Subject.CommonName; cn != certHost {
		t.Fatalf("证书CN=%q, 期望 %q", cn, certHost)
	}
}

// ---------- 路径遍历端到端（文件夹接收） ----------

// TestFolderTraversalRejected 模拟恶意发送方在 file_offer 中携带 ../ 相对路径，
// 接收端必须拒绝，且不得在任何逃逸位置创建文件。
func TestFolderTraversalRejected(t *testing.T) {
	t.Setenv(envConfigDir, t.TempDir())
	os.RemoveAll("received_files")
	t.Cleanup(func() { os.RemoveAll("received_files") })

	b := NewChatClient()
	b.SetName("Victim")
	b.SetPortBase(6600)
	logs := make(chan string, 64)
	b.OnLog = func(s string) {
		select {
		case logs <- s:
		default:
		}
	}
	b.Start()
	t.Cleanup(b.Stop)

	// 模拟恶意对端：TLS 连上后直接发 folder_offer + 带遍历路径的 file_offer
	go func() {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", b.TCPPort()), tlsClientConfig())
		if err != nil {
			t.Errorf("TLS拨号失败: %v", err)
			return
		}
		defer conn.Close()
		w := bufio.NewWriter(conn)
		send := func(msg map[string]any) {
			msg["from"] = "Attacker"
			data, _ := json.Marshal(msg)
			_, _ = w.Write(append(data, '\n'))
			_ = w.Flush()
		}
		// 先建立聊天会话（folder 文件不弹确认框，直接走自动接收路径）
		send(map[string]any{"type": "chat", "port": 67111, "content": "hi"})
		time.Sleep(300 * time.Millisecond)
		send(map[string]any{"type": "folder_offer", "folderName": "okfolder", "folderID": "f1",
			"folderSize": 1, "fileCount": 1})
		time.Sleep(300 * time.Millisecond)
		send(map[string]any{"type": "file_offer", "fileName": "evil.txt", "fileSize": 3,
			"fileID": "fx", "totalChunks": 1, "folderID": "f1",
			"relativePath": `..\..\..\evil_pwned.txt`, "proto": 2})
		time.Sleep(time.Second)
	}()

	// 接收端进入会话并"接受"文件夹（模拟用户点头；AcceptFolder 由测试直接调用）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !b.IsInChat() {
		time.Sleep(50 * time.Millisecond)
	}
	b.AcceptFolder("f1")

	time.Sleep(1500 * time.Millisecond)

	// 断言1：逃逸目标文件不存在
	if _, err := os.Stat("evil_pwned.txt"); err == nil {
		t.Fatal("路径遍历成功！逃逸文件被写到了接收目录之外")
	}
	if _, err := os.Stat(filepath.Join("..", "evil_pwned.txt")); err == nil {
		t.Fatal("路径遍历成功！逃逸文件被写到了上级目录")
	}
	// 断言2：接收目录顶层不应出现未清洗的逃逸文件
	entries, _ := os.ReadDir("received_files")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "evil_pwned") && !e.IsDir() {
			t.Fatalf("接收目录顶层出现了未清洗的逃逸文件: %s", e.Name())
		}
	}
}
