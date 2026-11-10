package types

// security.go 安全加固模块（电脑 ↔ 电脑通道）
//
// 1) TLS 加密传输：为本机生成/加载自签名证书，TCP 聊天与文件通道全部走 TLS，
//    防止局域网内被动嗅探聊天内容与文件数据。信任模型为局域网直连自签证书
//    （与 LocalSend 同类），不依赖公共 CA，离线可用。
// 2) 路径安全：对远端传来的文件名/相对路径做清洗与逃逸校验，
//    杜绝 ../、盘符、绝对路径、UNC 等路径遍历攻击。
//
// 注意：手机互传（gui/phone.go）不在此模块范围内，仍保持原有明文 HTTP 行为。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------- 配置/证书目录 ----------

const (
	// appDirName 应用数据目录名（位于系统标准用户配置目录下）
	appDirName = "LocalCP"
	// certHost 证书 CN，仅作标识，不参与主机名校验
	certHost = "localcp.local"
	// portMarkerFile 便携模式标记文件：与可执行文件同目录放置该文件即启用便携模式
	portableMarkerFile = "portable.txt"
	// portableDataDir 便携模式下的数据目录名（位于可执行文件同目录）
	portableDataDir = "LocalCP-data"
	// envConfigDir 环境变量覆盖项（便于测试与特殊部署）
	envConfigDir = "LOCALCP_CONFIG_DIR"
)

// configDir 返回本应用的持久化数据根目录（证书、密钥等）。
//
// 优先级：
//  1. 环境变量 LOCALCP_CONFIG_DIR（显式覆盖，测试/特殊部署用）
//  2. 便携模式：可执行文件同目录存在 portable.txt 时，用同目录下的 LocalCP-data
//  3. 系统标准用户配置目录（Windows: %APPDATA%\LocalCP；
//     Linux: ~/.config/LocalCP；macOS: ~/Library/Application Support/LocalCP）
//
// 关键点：**绝不使用当前工作目录**。否则从不同目录启动（双击 exe、命令行、go test
// 的不同包目录）会各自生成一套证书，导致同一台机器出现多个设备身份，
// 使任何指纹校验/设备去重失效。
func configDir() (string, error) {
	if env := strings.TrimSpace(os.Getenv(envConfigDir)); env != "" {
		dir := filepath.Clean(env)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", fmt.Errorf("创建配置目录失败(%s): %w", dir, err)
		}
		return dir, nil
	}

	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		if _, statErr := os.Stat(filepath.Join(base, portableMarkerFile)); statErr == nil {
			dir := filepath.Join(base, portableDataDir)
			if err := os.MkdirAll(dir, 0700); err == nil {
				return dir, nil
			}
		}
	}

	cfg, err := os.UserConfigDir()
	if err != nil || cfg == "" {
		return "", fmt.Errorf("无法定位用户配置目录，可用环境变量 %s 指定", envConfigDir)
	}
	dir := filepath.Join(cfg, appDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("创建配置目录失败(%s): %w", dir, err)
	}
	return dir, nil
}

// tlsDir 返回证书存放目录（配置目录下的 tls/ 子目录，权限 0700）
func tlsDir() (string, error) {
	root, err := configDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "tls")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("创建证书目录失败(%s): %w", dir, err)
	}
	return dir, nil
}

// ---------- TLS 证书 ----------

// ensureHostCertificate 加载或生成本机自签名证书。
// 证书持久化在配置目录的 tls/ 下，重启/升级后指纹稳定，为后续指纹固定(TOFU)留基础。
func ensureHostCertificate() (tls.Certificate, error) {
	dir, err := tlsDir()
	if err != nil {
		return tls.Certificate{}, err
	}
	certPath := filepath.Join(dir, "host.crt")
	keyPath := filepath.Join(dir, "host.key")

	// 复用已有证书（同时校验私钥与证书匹配、未过期）
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
			if time.Now().Before(leaf.NotAfter) {
				cert.Leaf = leaf
				return cert, nil
			}
			// 已过期：继续走下面的重新生成流程
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成TLS私钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成证书序列号失败: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: certHost, Organization: []string{"LocalCP"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{certHost},
		// 不写 IPAddresses：局域网 IP 会随网络变化，客户端按"局域网直连"信任模型处理
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("编码私钥失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// 私钥文件权限 0600：仅当前用户可读
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存证书失败: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存私钥失败: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
		cert.Leaf = leaf
	}
	return cert, nil
}

// CertInfo 本机 TLS 身份信息，用于启动时打日志，便于用户核对两端身份
type CertInfo struct {
	Path        string // 证书文件路径
	Fingerprint string // 证书 DER 的 SHA-256 指纹，大写十六进制（"AA:BB:..."）
}

// LocalCertInfo 返回本机证书路径与指纹（会触发证书加载/生成）
func LocalCertInfo() (CertInfo, error) {
	dir, err := tlsDir()
	if err != nil {
		return CertInfo{}, err
	}
	cert, err := ensureHostCertificate()
	if err != nil {
		return CertInfo{}, err
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return CertInfo{}, err
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	// 转成 AA:BB:CC... 形式，与 LocalSend 的指纹展示格式一致，便于人眼比对
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return CertInfo{Path: filepath.Join(dir, "host.crt"), Fingerprint: b.String()}, nil
}

// tlsServerConfig 服务端 TLS 配置（供 listener 使用）
func tlsServerConfig() *tls.Config {
	cert, err := ensureHostCertificate()
	if err != nil {
		// 仅在磁盘故障等极端情况走到这里：退回内存自签证书，保证通信仍然加密
		cert = mustEphemeralCert()
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// tlsClientConfig 客户端 TLS 配置（供 dial 使用）。
//
// InsecureSkipVerify：对端是局域网内临时设备的自签证书，无法走公共 CA 校验。
// 本方案的目标是「防被动嗅探 + 防传输篡改」；对端身份由 UDP 发现得到的局域网地址
// 与用户主动选择会话对象来保证。若要进一步做设备指纹固定(TOFU)，
// 可在 VerifyPeerCertificate 中比对已知指纹（见 LocalCertInfo 提供的格式）。
func tlsClientConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // 自签证书体系，理由见函数注释
		MinVersion:         tls.VersionTLS12,
		ServerName:         certHost,
	}
}

// mustEphemeralCert 兜底：内存自签证书（证书目录不可写时）
func mustEphemeralCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("无法生成TLS密钥: " + err.Error())
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: certHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		panic("无法生成TLS证书: " + err.Error())
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic("无法编码TLS私钥: " + err.Error())
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		panic("无法装配TLS密钥对: " + err.Error())
	}
	return cert
}

// ---------- 路径安全 ----------

// sanitizeFileName 清洗远端提供的单个文件名/文件夹名：
// 剥离任何目录成分，替换 Windows 非法字符，拒绝保留设备名与空名。
func sanitizeFileName(name string) (string, error) {
	// 统一分隔符后取最后一段，剥离任何目录成分（含 ../、..\、盘符路径）
	n := strings.ReplaceAll(name, "\\", "/")
	n = filepath.Base(n)
	n = strings.TrimSpace(n)

	var b strings.Builder
	for _, r := range n {
		switch {
		case r < 0x20 || r == 0x7f:
			// 丢弃控制字符
		case strings.ContainsRune(`/:*?"<>|`, r):
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	n = b.String()
	// 去掉结尾的点与空格（Windows 不允许）
	n = strings.TrimRight(n, ". ")

	if n == "" || n == "." || n == ".." {
		return "", fmt.Errorf("非法文件名: %q", name)
	}

	// Windows 保留设备名（CON、PRN、AUX、NUL、COM1-9、LPT1-9）
	stem := strings.SplitN(strings.ToUpper(n), ".", 2)[0]
	switch stem {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return "", fmt.Errorf("Windows保留设备名: %q", name)
	}
	return n, nil
}

// sanitizeRelativePath 清洗远端提供的文件夹内相对路径：
// 允许保留合法的子目录结构，但拒绝绝对路径、盘符、UNC 路径与任何 .. 逃逸。
// 返回以 / 分隔的安全相对路径（可直接交给 filepath.FromSlash）。
func sanitizeRelativePath(rel string) (string, error) {
	if strings.TrimSpace(rel) == "" {
		return "", errors.New("相对路径为空")
	}
	// 统一分隔符后再逐段清洗，覆盖 ..\、..\\ 等变体
	norm := strings.ReplaceAll(rel, "\\", "/")
	if strings.HasPrefix(norm, "//") {
		return "", fmt.Errorf("相对路径为UNC/双斜杠形态: %q", rel)
	}

	var cleaned []string
	for _, p := range strings.Split(norm, "/") {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return "", fmt.Errorf("相对路径含 .. 逃逸: %q", rel)
		}
		// 盘符（C:、c:）等含冒号的段直接拒绝
		if strings.ContainsRune(p, ':') {
			return "", fmt.Errorf("相对路径含盘符: %q", rel)
		}
		seg, err := sanitizeFileName(p)
		if err != nil {
			return "", fmt.Errorf("相对路径段非法 %q: %w", rel, err)
		}
		cleaned = append(cleaned, seg)
	}
	if len(cleaned) == 0 {
		return "", fmt.Errorf("相对路径清洗后为空: %q", rel)
	}
	return strings.Join(cleaned, "/"), nil
}

// safeJoinUnder 将清洗后的相对路径拼接到 base 目录下，
// 并做最终校验：结果必须仍位于 base 之内（深度防御，双保险）。
func safeJoinUnder(base, rel string) (string, error) {
	cleanRel, err := sanitizeRelativePath(rel)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(base, filepath.FromSlash(cleanRel))

	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	relBack, err := filepath.Rel(absBase, absJoined)
	if err != nil {
		return "", err
	}
	if relBack == ".." || strings.HasPrefix(relBack, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("路径逃逸: %q -> %q", rel, joined)
	}
	return joined, nil
}
