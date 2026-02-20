package main

import (
	"archive/zip"
	"bufio"
	_ "embed" // Used for admin.html embedding
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed admin.html
var adminHTML string

const (
	DefaultPubPort = 3097
	WebPort        = 31000
	ProxyPort      = 31001
)

type FileItem struct {
	Name        string `json:"name"`
	IsDirectory bool   `json:"isDirectory"`
	Size        int64  `json:"size"`
	Mtime       string `json:"mtime"`
}

type AppConfig struct {
	Auth    AuthConfig         `json:"auth"`
	WebPort int                `json:"webPort"`
	Port    int                `json:"port"`
	Token   string             `json:"token"`
	Tools   map[string]ToolCfg `json:"tools"`
	Logs    LogConfig          `json:"logs"`
}

type LogConfig struct {
	Enabled  bool `json:"enabled"`
	LogTools bool `json:"logTools"`
	LogBots  bool `json:"logBots"`
	LogApi   bool `json:"logApi"`
	LogProbe bool `json:"logProbe"`
	MaxLines int  `json:"maxLines"`
}

type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ToolCfg struct {
	Enabled               bool                   `json:"enabled"`
	AutoStart             bool                   `json:"autoStart"`
	AutoDelete            bool                   `json:"autoDelete"`
	Token                 string                 `json:"token"`
	Mode                  string                 `json:"mode"`
	LocalPort             int                    `json:"localPort"`
	Protocol              string                 `json:"protocol"`
	Server                string                 `json:"server"`
	Key                   string                 `json:"key"`
	Version               string                 `json:"version"`
	Auth                  string                 `json:"auth"`
	ListenPort            int                    `json:"listenPort"`
	PublicPort            int                    `json:"publicPort"`
	TargetAddr            string                 `json:"targetAddr"`
	RemoteServer          string                 `json:"remoteServer"`
	TunnelPort            int                    `json:"tunnelPort"`
	ExposedPort           int                    `json:"exposedPort"`
	TunnelMultiplex       bool                   `json:"tunnelMultiplex"`
	Protocols             map[string]ProtocolCfg `json:"protocols"`
	UseCF                 bool                   `json:"useCF"`
	Insecure              bool                   `json:"insecure"`
	Tls                   bool                   `json:"tls"`
	Gpu                   bool                   `json:"gpu"`
	Temperature           bool                   `json:"temperature"`
	UseIPv6               bool                   `json:"useIPv6"`
	DisableAutoUpdate     bool                   `json:"disableAutoUpdate"`
	DisableCommandExecute bool                   `json:"disableCommandExecute"`
	LocalAddr             string                 `json:"localAddr"`
	P4                    ProtocolCfg            `json:"p4"`
	P5                    ProtocolCfg            `json:"p5"`
	Port                  int                    `json:"port"`
	UUID                  string                 `json:"uuid"`
	NodeName              string                 `json:"nodeName"`
	PreferredDomain       string                 `json:"preferredDomain"`
	Domain                string                 `json:"domain"`
	TunnelUrl             string                 `json:"tunnelUrl"`
	ISPInfo               string                 `json:"ispInfo"`
	PublicIp              string                 `json:"publicIp"`
	DownloadUrl           string                 `json:"downloadUrl"`
	SSMethod              string                 `json:"ssMethod"`
}

type LogEntry struct {
	Time  string `json:"time"`
	Type  string `json:"type"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

type ProtocolCfg struct {
	Enabled bool   `json:"enabled"`
	WsPath  string `json:"wsPath"`
	Port    int    `json:"port"`
}

type ArchInfo struct {
	Platform string `json:"platform"`
	ArchName string `json:"archName"`
}

type ShareLink struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Link     string `json:"link"`
}

var (
	GlobalConfig AppConfig
	DataDir      = "data"
	ConfigPath   = filepath.Join(DataDir, "config.json")
	XorSecret    = "minebot-toolbox-xor-key-2024"
	FileMapPath  = filepath.Join(DataDir, "filemap.dat")
	fileMap      = make(map[string]string)
	pids         = make(map[string]*exec.Cmd)
	logBuffers   = make(map[string]*CircularBuffer)
	logs         []LogEntry
	pidMu        sync.Mutex
	logMu        sync.Mutex
)

func initPaths() {
	exeDir := getExternRoot()
	exeData := filepath.Join(exeDir, "data")
	cwd, _ := os.Getwd()
	cwdData := filepath.Join(cwd, "data")
	useExe := true
	if _, err := os.Stat(filepath.Join(exeData, "config.json")); err == nil {
		useExe = true
	} else if _, err := os.Stat(filepath.Join(cwdData, "config.json")); err == nil {
		useExe = false
	}
	if useExe {
		DataDir = exeData
	} else {
		DataDir = cwdData
	}
	ConfigPath = filepath.Join(DataDir, "config.json")
	FileMapPath = filepath.Join(DataDir, "filemap.dat")
}

func getExternRoot() string {
	exe, err := os.Executable()
	if err != nil {
		cwd, _ := os.Getwd()
		return cwd
	}
	return filepath.Dir(exe)
}

type CircularBuffer struct {
	lines []string
	size  int
	head  int
	mu    sync.Mutex
}

func NewCircularBuffer(size int) *CircularBuffer {
	return &CircularBuffer{lines: make([]string, 0, size), size: size}
}

func (cb *CircularBuffer) Add(line string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if len(cb.lines) < cb.size {
		cb.lines = append(cb.lines, line)
	} else {
		cb.lines[cb.head] = line
		cb.head = (cb.head + 1) % cb.size
	}
}

func (cb *CircularBuffer) GetLines() []string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	res := make([]string, 0, len(cb.lines))
	l := len(cb.lines)
	if l == 0 {
		return res
	}
	for i := 0; i < l; i++ {
		idx := (cb.head + i) % l
		res = append(res, cb.lines[idx])
	}
	return res
}

// XOR & Config Utils
func decodeB64(e string) string {
	d, _ := base64.StdEncoding.DecodeString(e)
	return string(d)
}

func genRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(1 * time.Nanosecond) // Slight stagger for better "randomness" without math/rand
	}
	return string(b)
}

func xorProcessor(text string) string {
	res := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		res[i] = text[i] ^ XorSecret[i%len(XorSecret)]
	}
	return string(res)
}

func xorEncrypt(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(xorProcessor(text)))
}

func xorDecrypt(encoded string) string {
	d, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return xorProcessor(string(d))
}

func loadFileMap() {
	data, err := os.ReadFile(FileMapPath)
	if err == nil {
		decoded := xorDecrypt(string(data))
		json.Unmarshal([]byte(decoded), &fileMap)
	}
}

func saveFileMap() {
	data, _ := json.Marshal(fileMap)
	encoded := xorEncrypt(string(data))
	os.WriteFile(FileMapPath, []byte(encoded), 0644)
}

func getRandomFileName(originalName, kind string) string {
	key := kind + ":" + originalName
	if name, ok := fileMap[key]; ok {
		return name
	}
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = chars[time.Now().UnixNano()%int64(len(chars))]
		time.Sleep(1 * time.Nanosecond)
	}
	name := string(b)
	fileMap[key] = name
	saveFileMap()
	return name
}

func loadConfig() error {
	data, err := os.ReadFile(ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(DataDir, 0755)
			GlobalConfig = AppConfig{
				Auth: AuthConfig{
					Username: "admin",
					Password: "admin123",
				},
				WebPort: WebPort,
				Port:    DefaultPubPort,
				Tools:   make(map[string]ToolCfg),
				Logs: LogConfig{
					Enabled:  true,
					LogTools: true,
					LogBots:  true,
					LogApi:   false,
					LogProbe: true,
					MaxLines: 500,
				},
			}
			return saveConfig()
		}
		return err
	}
	decoded := xorDecrypt(string(data))
	var raw map[string]interface{}
	_ = json.Unmarshal([]byte(decoded), &raw)
	err = json.Unmarshal([]byte(decoded), &GlobalConfig)
	if err != nil {
		GlobalConfig = AppConfig{
			Auth: AuthConfig{
				Username: "admin",
				Password: "admin123",
			},
			WebPort: WebPort,
			Port:    DefaultPubPort,
			Tools:   make(map[string]ToolCfg),
			Logs: LogConfig{
				Enabled:  true,
				LogTools: true,
				LogBots:  true,
				LogApi:   false,
				LogProbe: true,
				MaxLines: 500,
			},
		}
		// Default Sing-box cfg
		GlobalConfig.Tools["sing-box"] = ToolCfg{
			UUID: genRandomString(16),
			Key:  genRandomString(12),
			Port: 8001,
			Protocols: map[string]ProtocolCfg{
				"p0": {Enabled: true, WsPath: "/p0"},
				"p1": {Enabled: false, WsPath: "/p1"},
				"p2": {Enabled: false, WsPath: "/p2"},
				"p3": {Enabled: false, Port: 8004},
			},
		}
		return saveConfig()
	}
	logsUnset := !GlobalConfig.Logs.Enabled && !GlobalConfig.Logs.LogTools && !GlobalConfig.Logs.LogBots && !GlobalConfig.Logs.LogApi && GlobalConfig.Logs.MaxLines == 0
	if logsUnset {
		GlobalConfig.Logs = LogConfig{
			Enabled:  true,
			LogTools: true,
			LogBots:  true,
			LogApi:   false,
			LogProbe: true,
			MaxLines: 500,
		}
	}

	if GlobalConfig.WebPort == 0 {
		GlobalConfig.WebPort = WebPort
	}
	if GlobalConfig.Port == 0 {
		GlobalConfig.Port = DefaultPubPort
	}
	if GlobalConfig.Logs.MaxLines == 0 {
		GlobalConfig.Logs.MaxLines = 500
	}

	// Migration for old config
	for name, tool := range GlobalConfig.Tools {
		modified := false
		var rawTool map[string]interface{}
		if toolsRaw, ok := raw["tools"].(map[string]interface{}); ok {
			if rt, ok := toolsRaw[name].(map[string]interface{}); ok {
				rawTool = rt
			}
		}
		if tool.Protocols != nil {
			maps := map[string]string{"vless": "p0", "vmess": "p1", "trojan": "p2", "socks": "p3"}
			for old, newKey := range maps {
				if v, ok := tool.Protocols[old]; ok {
					tool.Protocols[newKey] = v
					delete(tool.Protocols, old)
					modified = true
				}
			}
		}
		// If using old 'Password' field (mistakenly used earlier), migrate back to 'Key' logic if needed
		// But since we reverted struct to Key, json unmarshal handles 'key' from file correctly.
		// We just ensure Key is present for Sing-box
		if name == "sing-box" && tool.Key == "" {
			tool.Key = genRandomString(12)
			modified = true
		}
		if name == "nezha" && tool.Version == "" {
			tool.Version = "v1"
			modified = true
		}
		if name == "nezha" && rawTool != nil {
			if _, ok := rawTool["disableAutoUpdate"]; !ok || !tool.DisableAutoUpdate {
				tool.DisableAutoUpdate = true
				modified = true
			}
		}
		if name == "komari" && rawTool != nil {
			if _, ok := rawTool["disableAutoUpdate"]; !ok || !tool.DisableAutoUpdate {
				tool.DisableAutoUpdate = true
				modified = true
			}
		}
		if modified {
			GlobalConfig.Tools[name] = tool
		}
	}
	if len(GlobalConfig.Tools) > 0 {
		saveConfig()
	}
	return nil
}

func logEvent(category, level, msg string) {
	if !GlobalConfig.Logs.Enabled {
		return
	}
	if category == "tool" && !GlobalConfig.Logs.LogTools {
		return
	}
	if category == "bot" && !GlobalConfig.Logs.LogBots {
		return
	}
	if category == "api" && !GlobalConfig.Logs.LogApi {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	entry := LogEntry{Time: time.Now().Format(time.RFC3339), Type: category, Level: level, Msg: msg}
	logs = append(logs, entry)
	maxLines := GlobalConfig.Logs.MaxLines
	if maxLines <= 0 {
		maxLines = 500
	}
	if len(logs) > maxLines {
		logs = logs[len(logs)-maxLines:]
	}
}

func saveConfig() error {
	data, err := json.MarshalIndent(GlobalConfig, "", "  ")
	if err != nil {
		return err
	}
	encoded := xorEncrypt(string(data))
	return os.WriteFile(ConfigPath, []byte(encoded), 0644)
}

func isInstalled(name string) bool {
	binPath := filepath.Join(DataDir, "bin", getRandomFileName(name, "bin"))
	if name == "sing-box" || name == "nezha" || name == "komari" || name == "gost" {
		if _, err := os.Stat(binPath); err == nil {
			return true
		}
	} else if name == "cf-tunnel" {
		if _, err := os.Stat(binPath); err == nil {
			return true
		}
	}
	return false
}

func deleteCerts() {
	_ = os.Remove(filepath.Join(DataDir, "cert.pem"))
	_ = os.Remove(filepath.Join(DataDir, "key.pem"))
}

// Helpers
func downloadFile(url, dest string) error {
	logEvent("tool", "info", "[download] "+url)
	resp, err := http.Get(url)
	if err != nil {
		logEvent("tool", "error", "[download] failed: "+err.Error())
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logEvent("tool", "error", "[download] bad status: "+resp.Status)
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	out, err := os.Create(dest)
	if err != nil {
		logEvent("tool", "error", "[download] create failed: "+err.Error())
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		logEvent("tool", "error", "[download] copy failed: "+err.Error())
	}
	return err
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func startToolProcess(name, binPath string, args []string) error {
	pidMu.Lock()
	if cmd, ok := pids[name]; ok && cmd.Process != nil {
		cmd.Process.Kill()
	}
	pidMu.Unlock()

	cmd := exec.Command(binPath, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if logBuffers[name] == nil {
		logBuffers[name] = NewCircularBuffer(500)
	}

	stream := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		category := "tool"
		if name == "nezha" || name == "komari" {
			category = "probe"
		}
		for scanner.Scan() {
			line := scanner.Text()
			logBuffers[name].Add(line)
			logEvent(category, "info", "["+name+"] "+line)
		}
	}
	go stream(stdout)
	go stream(stderr)

	err := cmd.Start()
	if err != nil {
		return err
	}

	pidMu.Lock()
	pids[name] = cmd
	pidMu.Unlock()

	go func() {
		cmd.Wait()
		pidMu.Lock()
		if pids[name] == cmd {
			delete(pids, name)
		}
		pidMu.Unlock()
		logEvent("tool", "info", "["+name+"] 进程已退出")
	}()
	return nil
}

func stopToolProcess(name string) {
	pidMu.Lock()
	defer pidMu.Unlock()
	if cmd, ok := pids[name]; ok {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		delete(pids, name)
	}
}

func scheduleAutoDelete(name string, deleteFunc func()) {
	logEvent("tool", "info", "["+name+"] 60秒后自动清理文件")
	go func() {
		time.Sleep(60 * time.Second)
		deleteFunc()
		logEvent("tool", "info", "["+name+"] 文件已清理")
	}()
}

func defaultToolCfg(name string) ToolCfg {
	switch name {
	case "cf-tunnel":
		return ToolCfg{
			Enabled:    false,
			Mode:       "fixed",
			Token:      "",
			Domain:     "",
			Protocol:   "http",
			LocalPort:  8001,
			AutoStart:  false,
			AutoDelete: false,
		}
	case "sing-box":
		return ToolCfg{
			Enabled:         false,
			AutoStart:       false,
			AutoDelete:      false,
			Mode:            "auto",
			Port:            8001,
			UUID:            "",
			Key:             "",
			SSMethod:        "aes-256-gcm",
			UseCF:           false,
			PreferredDomain: "",
			Protocols: map[string]ProtocolCfg{
				"p0": {Enabled: false, WsPath: "/p0"},
				"p1": {Enabled: false, WsPath: "/p1"},
				"p2": {Enabled: false, WsPath: "/p2"},
				"p3": {Enabled: false, WsPath: "/p3", Port: 0},
			},
			P4: ProtocolCfg{Enabled: false, Port: 0},
			P5: ProtocolCfg{Enabled: false, Port: 0},
		}
	case "nezha":
		return ToolCfg{
			Enabled:               false,
			Version:               "v1",
			Server:                "",
			Key:                   "",
			Tls:                   true,
			Insecure:              false,
			Gpu:                   false,
			Temperature:           false,
			UseIPv6:               false,
			DisableAutoUpdate:     true,
			DisableCommandExecute: false,
			AutoStart:             false,
			AutoDelete:            false,
			DownloadUrl:           "",
		}
	case "komari":
		return ToolCfg{
			Enabled:           false,
			Server:            "",
			Key:               "",
			Insecure:          false,
			Gpu:               false,
			DisableAutoUpdate: true,
			AutoStart:         false,
			AutoDelete:        false,
		}
	case "gost":
		return ToolCfg{
			Enabled:         false,
			Mode:            "tunnel",
			ListenPort:      0,
			PublicPort:      0,
			TargetAddr:      "",
			Auth:            "",
			AutoStart:       false,
			AutoDelete:      false,
			TunnelPort:      0,
			ExposedPort:     0,
			LocalAddr:       "127.0.0.1:80",
			RemoteServer:    "",
			TunnelMultiplex: true,
		}
	default:
		return ToolCfg{}
	}
}

func getTmpDir() string {
	tmpDir := filepath.Join(DataDir, "tmp")
	_ = os.MkdirAll(tmpDir, 0755)
	return tmpDir
}

func cleanupTmpFile(path string) {
	if path == "" {
		return
	}
	go func() {
		time.Sleep(2 * time.Second)
		_ = os.Remove(path)
	}()
}

func mergeToolCfgWithRaw(dst ToolCfg, src ToolCfg, raw map[string]json.RawMessage) ToolCfg {
	if _, ok := raw["enabled"]; ok {
		dst.Enabled = src.Enabled
	}
	if _, ok := raw["autoStart"]; ok {
		dst.AutoStart = src.AutoStart
	}
	if _, ok := raw["autoDelete"]; ok {
		dst.AutoDelete = src.AutoDelete
	}
	if _, ok := raw["token"]; ok {
		dst.Token = src.Token
	}
	if _, ok := raw["mode"]; ok {
		dst.Mode = src.Mode
	}
	if _, ok := raw["localPort"]; ok {
		dst.LocalPort = src.LocalPort
	}
	if _, ok := raw["protocol"]; ok {
		dst.Protocol = src.Protocol
	}
	if _, ok := raw["server"]; ok {
		dst.Server = src.Server
	}
	if _, ok := raw["key"]; ok {
		dst.Key = src.Key
	}
	if _, ok := raw["version"]; ok {
		dst.Version = src.Version
	}
	if _, ok := raw["auth"]; ok {
		dst.Auth = src.Auth
	}
	if _, ok := raw["listenPort"]; ok {
		dst.ListenPort = src.ListenPort
	}
	if _, ok := raw["publicPort"]; ok {
		dst.PublicPort = src.PublicPort
	}
	if _, ok := raw["targetAddr"]; ok {
		dst.TargetAddr = src.TargetAddr
	}
	if _, ok := raw["remoteServer"]; ok {
		dst.RemoteServer = src.RemoteServer
	}
	if _, ok := raw["tunnelPort"]; ok {
		dst.TunnelPort = src.TunnelPort
	}
	if _, ok := raw["exposedPort"]; ok {
		dst.ExposedPort = src.ExposedPort
	}
	if _, ok := raw["tunnelMultiplex"]; ok {
		dst.TunnelMultiplex = src.TunnelMultiplex
	}
	if _, ok := raw["protocols"]; ok {
		dst.Protocols = src.Protocols
	}
	if _, ok := raw["useCF"]; ok {
		dst.UseCF = src.UseCF
	}
	if _, ok := raw["insecure"]; ok {
		dst.Insecure = src.Insecure
	}
	if _, ok := raw["tls"]; ok {
		dst.Tls = src.Tls
	}
	if _, ok := raw["gpu"]; ok {
		dst.Gpu = src.Gpu
	}
	if _, ok := raw["temperature"]; ok {
		dst.Temperature = src.Temperature
	}
	if _, ok := raw["useIPv6"]; ok {
		dst.UseIPv6 = src.UseIPv6
	}
	if _, ok := raw["disableAutoUpdate"]; ok {
		dst.DisableAutoUpdate = src.DisableAutoUpdate
	}
	if _, ok := raw["disableCommandExecute"]; ok {
		dst.DisableCommandExecute = src.DisableCommandExecute
	}
	if _, ok := raw["localAddr"]; ok {
		dst.LocalAddr = src.LocalAddr
	}
	if _, ok := raw["p4"]; ok {
		dst.P4 = src.P4
	}
	if _, ok := raw["p5"]; ok {
		dst.P5 = src.P5
	}
	if _, ok := raw["port"]; ok {
		dst.Port = src.Port
	}
	if _, ok := raw["uuid"]; ok {
		dst.UUID = src.UUID
	}
	if _, ok := raw["nodeName"]; ok {
		dst.NodeName = src.NodeName
	}
	if _, ok := raw["preferredDomain"]; ok {
		dst.PreferredDomain = src.PreferredDomain
	}
	if _, ok := raw["domain"]; ok {
		dst.Domain = src.Domain
	}
	if _, ok := raw["tunnelUrl"]; ok {
		dst.TunnelUrl = src.TunnelUrl
	}
	if _, ok := raw["ispInfo"]; ok {
		dst.ISPInfo = src.ISPInfo
	}
	if _, ok := raw["publicIp"]; ok {
		dst.PublicIp = src.PublicIp
	}
	if _, ok := raw["downloadUrl"]; ok {
		dst.DownloadUrl = src.DownloadUrl
	}
	if _, ok := raw["ssMethod"]; ok {
		dst.SSMethod = src.SSMethod
	}
	return dst
}

// Global Mappings & Logic
const (
	DL_CF       = "aHR0cHM6Ly9naXRodWIuY29tL2Nsb3VkZmxhcmUvY2xvdWRmbGFyZWQvcmVsZWFzZXMvbGF0ZXN0L2Rvd25sb2Fk"
	DL_CF_WIN   = "Y2xvdWRmbGFyZWQtd2luZG93cy1hbWQ2NC5leGU="
	DL_CF_MAC   = "Y2xvdWRmbGFyZWQtZGFyd2luLWFtZDY0LnRneg=="
	DL_CF_LINUX = "Y2xvdWRmbGFyZWQtbGludXgt"
	DL_CF_CMD   = "dHVubmVs"
	DL_SB_AMD   = "aHR0cHM6Ly9naXRodWIuY29tL2Vvb2NlL3Rlc3QvcmVsZWFzZXMvZG93bmxvYWQvYW1kNjQvc2J4"
	DL_SB_ARM   = "aHR0cHM6Ly9naXRodWIuY29tL2Vvb2NlL3Rlc3QvcmVsZWFzZXMvZG93bmxvYWQvYXJtNjQvc2J4"

	DL_GS_AMD = "aHR0cHM6Ly9naXRodWIuY29tL2Nva2Vhci9tdXNpYy1wbGF5ZXIvcmVsZWFzZXMvZG93bmxvYWQvZ29zdC1sYXRlc3QvZ29zdC1hbWQ2NA=="
	DL_GS_ARM = "aHR0cHM6Ly9naXRodWIuY29tL2Nva2Vhci9tdXNpYy1wbGF5ZXIvcmVsZWFzZXMvZG93bmxvYWQvZ29zdC1sYXRlc3QvZ29zdC1hcm02NA=="

	DL_NZ_AMD_V1 = "aHR0cHM6Ly9hbWQ2NC5zc3NzLm55Yy5tbi92MQ=="
	DL_NZ_ARM_V1 = "aHR0cHM6Ly9hcm02NC5zc3NzLm55Yy5tbi92MQ=="
	DL_NZ_AMD_V0 = "aHR0cHM6Ly9hbWQ2NC5zc3NzLm55Yy5tbi9hZ2VudA=="
	DL_NZ_ARM_V0 = "aHR0cHM6Ly9hcm02NC5zc3NzLm55Yy5tbi9hZ2VudA=="

	DL_KM     = "aHR0cHM6Ly9naXRodWIuY29tL2tvbWFyaS1tb25pdG9yL2tvbWFyaS1hZ2VudC9yZWxlYXNlcy9sYXRlc3QvZG93bmxvYWQv"
	DL_KM_PRE = "a29tYXJpLWFnZW50LQ=="
	DL_KM_WIN = "d2luZG93cy1hbWQ2NC5leGU="
	DL_KM_MAC = "ZGFyd2luLWFtZDY0"
	DL_KM_LIN = "bGludXgt"
)

func ensureCert() {
	certFile := filepath.Join(DataDir, "cert.pem")
	keyFile := filepath.Join(DataDir, "key.pem")
	if _, err := os.Stat(certFile); err == nil {
		return
	}
	cmd := fmt.Sprintf("openssl req -x509 -newkey rsa:2048 -keyout \"%s\" -out \"%s\" -sha256 -days 3650 -nodes -subj \"/CN=minebot-toolbox\"", keyFile, certFile)
	exec.Command("sh", "-c", cmd).Run()
	exec.Command("powershell", "-Command", cmd).Run()
}

// Cloudflared Tool
func getCfBin() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return filepath.Join(DataDir, "bin", getRandomFileName("cf-tunnel", "bin")+ext)
}

func installCf() error {
	arch := runtime.GOARCH
	var url string
	if runtime.GOOS == "windows" {
		url = decodeB64(DL_CF) + "/" + decodeB64(DL_CF_WIN)
	} else if runtime.GOOS == "darwin" {
		url = decodeB64(DL_CF) + "/" + decodeB64(DL_CF_MAC)
	} else {
		suffix := "amd64"
		if arch == "arm64" {
			suffix = "arm64"
		}
		url = decodeB64(DL_CF) + "/" + decodeB64(DL_CF_LINUX) + suffix
	}
	binPath := getCfBin()
	os.MkdirAll(filepath.Dir(binPath), 0755)
	err := downloadFile(url, binPath)
	if err == nil && runtime.GOOS != "windows" {
		os.Chmod(binPath, 0755)
	}
	return err
}

func startCf() error {
	cfg := GlobalConfig.Tools["cf-tunnel"]
	binPath := getCfBin()
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		if err := installCf(); err != nil {
			return err
		}
	}
	var args []string
	if cfg.Mode == "quick" {
		args = []string{decodeB64(DL_CF_CMD), "--url", fmt.Sprintf("%s://localhost:%d", cfg.Protocol, cfg.LocalPort)}
		logEvent("tool", "info", "[cf-tunnel] mode=quick url="+fmt.Sprintf("%s://localhost:%d", cfg.Protocol, cfg.LocalPort))
	} else {
		args = []string{decodeB64(DL_CF_CMD), "--no-autoupdate", "run", "--token", cfg.Token}
		logEvent("tool", "info", "[cf-tunnel] mode=fixed")
	}
	err := startToolProcess("cf-tunnel", binPath, args)
	if err != nil {
		logEvent("tool", "error", "[cf-tunnel] 启动失败: "+err.Error())
		if cfg.AutoDelete {
			os.Remove(binPath)
			deleteCerts()
		}
		return err
	}
	cfg.Enabled = true
	GlobalConfig.Tools["cf-tunnel"] = cfg
	saveConfig()
	logEvent("tool", "info", "[cf-tunnel] 已启动")
	if cfg.AutoDelete {
		scheduleAutoDelete("cf-tunnel", func() {
			os.Remove(binPath)
			deleteCerts()
		})
	}
	return nil
}

// Sing-box Tool
func genS1Cfg(cfg ToolCfg) map[string]interface{} {
	inbounds := []interface{}{}
	port := cfg.Port
	if port == 0 {
		port = 8001
	}
	uuid := cfg.UUID
	password := cfg.Key

	certFile := filepath.Join(DataDir, "cert.pem")
	keyFile := filepath.Join(DataDir, "key.pem")

	wsEnabled := false
	if p, ok := cfg.Protocols["p0"]; ok && p.Enabled {
		path := p.WsPath
		if path == "" {
			path = "/p0"
		}
		inbounds = append(inbounds, map[string]interface{}{
			"type": "vless", "tag": "vless-in", "listen": "::", "listen_port": port,
			"users":     []interface{}{map[string]interface{}{"uuid": uuid}},
			"transport": map[string]interface{}{"type": "ws", "path": path},
		})
		wsEnabled = true
	}
	if p, ok := cfg.Protocols["p1"]; ok && p.Enabled {
		path := p.WsPath
		if path == "" {
			path = "/p1"
		}
		pPort := port
		if wsEnabled {
			pPort = port + 1
		}
		inbounds = append(inbounds, map[string]interface{}{
			"type": "vmess", "tag": "vmess-in", "listen": "::", "listen_port": pPort,
			"users":     []interface{}{map[string]interface{}{"uuid": uuid}},
			"transport": map[string]interface{}{"type": "ws", "path": path},
		})
		if !wsEnabled {
			wsEnabled = true
		}
	}
	if p, ok := cfg.Protocols["p2"]; ok && p.Enabled {
		path := p.WsPath
		if path == "" {
			path = "/p2"
		}
		pPort := port
		if wsEnabled {
			pPort = port + 2
		}
		inbounds = append(inbounds, map[string]interface{}{
			"type": "trojan", "tag": "trojan-in", "listen": "::", "listen_port": pPort,
			"password":  password,
			"transport": map[string]interface{}{"type": "ws", "path": path},
		})
		if !wsEnabled {
			wsEnabled = true
		}
	}
	if p, ok := cfg.Protocols["p3"]; ok && p.Enabled {
		socksPort := p.Port
		if socksPort == 0 {
			if wsEnabled {
				socksPort = port + 3
			} else {
				socksPort = port
			}
		}
		inbounds = append(inbounds, map[string]interface{}{
			"type": "socks", "tag": "socks-in", "listen": "::", "listen_port": socksPort,
			"users": []interface{}{map[string]interface{}{"username": uuid, "password": password}},
		})
	}
	if cfg.P4.Enabled && cfg.P4.Port != 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": cfg.P4.Port,
			"password": password,
			"tls":      map[string]interface{}{"enabled": true, "certificate_path": certFile, "key_path": keyFile},
		})
	}
	if cfg.P5.Enabled && cfg.P5.Port != 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": cfg.P5.Port,
			"users":              []interface{}{map[string]interface{}{"uuid": uuid, "password": password}},
			"congestion_control": "bbr",
			"tls":                map[string]interface{}{"enabled": true, "alpn": []string{"h3"}, "certificate_path": certFile, "key_path": keyFile},
		})
	}

	return map[string]interface{}{
		"log":      map[string]interface{}{"level": "info", "timestamp": true},
		"inbounds": inbounds,
		"outbounds": []interface{}{
			map[string]interface{}{"type": "direct", "tag": "direct"},
			map[string]interface{}{"type": "block", "tag": "block"},
		},
	}
}

func startSingBox() error {
	cfg := GlobalConfig.Tools["sing-box"]
	logEvent("tool", "info", "[sing-box] start requested")
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("sing-box", "bin"))
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		if err := installSingBox(); err != nil {
			return err
		}
	}

	hasProtocol := false
	if cfg.Protocols != nil {
		for _, p := range cfg.Protocols {
			if p.Enabled {
				hasProtocol = true
				break
			}
		}
	}
	if cfg.P4.Enabled || cfg.P5.Enabled {
		hasProtocol = true
	}
	if !hasProtocol {
		return fmt.Errorf("请至少启用一个协议")
	}

	if cfg.P4.Enabled && cfg.P4.Port == 0 {
		if port := findAvailablePort(20000, 65535); port != 0 {
			cfg.P4.Port = port
		}
	}
	if cfg.P5.Enabled && cfg.P5.Port == 0 {
		if port := findAvailablePort(30000, 65535); port != 0 {
			cfg.P5.Port = port
		}
	}
	if cfg.P4.Enabled || cfg.P5.Enabled {
		GlobalConfig.Tools["sing-box"] = cfg
		saveConfig()
	}

	// Generate UUID/Key if missing
	changed := false
	if cfg.UUID == "" {
		cfg.UUID = genRandomString(16) // Better than unix substitute
		changed = true
	}
	if cfg.Key == "" {
		cfg.Key = genRandomString(12)
		changed = true
	}
	if changed {
		GlobalConfig.Tools["sing-box"] = cfg
		saveConfig()
	}

	ensureCert()
	genConfig := genS1Cfg(cfg)
	data, _ := json.MarshalIndent(genConfig, "", "  ")
	plainPath := filepath.Join(getTmpDir(), getRandomFileName("sing-box-plain", "cfg")+".json")
	os.WriteFile(plainPath, data, 0644)
	err := startToolProcess("sing-box", binPath, []string{"run", "-c", plainPath})
	if err != nil {
		logEvent("tool", "error", "[sing-box] 启动失败: "+err.Error())
		if cfg.AutoDelete {
			os.Remove(binPath)
			deleteCerts()
		}
		return err
	}
	cleanupTmpFile(plainPath)
	cfg.Enabled = true
	GlobalConfig.Tools["sing-box"] = cfg
	saveConfig()
	logEvent("tool", "info", "[sing-box] 已启动")
	go updateSingBoxISPInfo()
	if cfg.UseCF {
		pidMu.Lock()
		_, running := pids["cf-tunnel"]
		pidMu.Unlock()
		if !running {
			cfCfg := GlobalConfig.Tools["cf-tunnel"]
			if cfCfg.Mode == "fixed" && cfCfg.Token != "" {
				_ = startCf()
			} else {
				cfCfg.Mode = "quick"
				cfCfg.LocalPort = cfg.Port
				cfCfg.Protocol = "http"
				cfCfg.Enabled = true
				GlobalConfig.Tools["cf-tunnel"] = cfCfg
				saveConfig()
				_ = startCf()
			}
		}
	}
	if cfg.AutoDelete {
		scheduleAutoDelete("sing-box", func() {
			os.Remove(binPath)
			deleteCerts()
		})
	}
	return nil
}

func updateSingBoxISPInfo() {
	client := &http.Client{Timeout: 5 * time.Second}
	setInfo := func(ip, isp, country string) bool {
		if ip == "" || country == "" {
			return false
		}
		cfg := GlobalConfig.Tools["sing-box"]
		cfg.PublicIp = ip
		cleanISP := strings.ReplaceAll(isp, " ", "_")
		if cleanISP == "" {
			cleanISP = "Unknown"
		}
		cfg.ISPInfo = country + "_" + cleanISP
		GlobalConfig.Tools["sing-box"] = cfg
		saveConfig()
		return true
	}
	fetchJSON := func(url string) map[string]interface{} {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		res, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer res.Body.Close()
		var data map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
			return nil
		}
		return data
	}
	if data := fetchJSON("https://api.ip.sb/geoip"); data != nil {
		country, _ := data["country_code"].(string)
		ip, _ := data["ip"].(string)
		isp, _ := data["isp"].(string)
		if setInfo(ip, isp, country) {
			return
		}
	}
	if data := fetchJSON("https://ipapi.co/json/"); data != nil {
		country, _ := data["country_code"].(string)
		ip, _ := data["ip"].(string)
		isp, _ := data["org"].(string)
		if setInfo(ip, isp, country) {
			return
		}
	}
	if data := fetchJSON("http://ip-api.com/json/"); data != nil {
		status, _ := data["status"].(string)
		if status == "success" {
			country, _ := data["countryCode"].(string)
			ip, _ := data["query"].(string)
			isp, _ := data["org"].(string)
			if isp == "" {
				isp, _ = data["isp"].(string)
			}
			setInfo(ip, isp, country)
		}
	}
}

func installSingBox() error {
	url := decodeB64(DL_SB_AMD)
	if runtime.GOARCH == "arm64" {
		url = decodeB64(DL_SB_ARM)
	}
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("sing-box", "bin"))
	os.MkdirAll(filepath.Dir(binPath), 0755)
	if err := downloadFile(url, binPath); err != nil {
		return err
	}
	return os.Chmod(binPath, 0755)
}

func resolveNezhaDownloadURL(cfg ToolCfg) string {
	if cfg.DownloadUrl != "" {
		url := cfg.DownloadUrl
		archSuffix := "v1-x64"
		if runtime.GOARCH == "arm64" {
			archSuffix = "v1-a64"
		}
		if strings.Contains(url, "${arch}") {
			return strings.ReplaceAll(url, "${arch}", archSuffix)
		}
		if strings.HasSuffix(url, "/") {
			return url + archSuffix
		}
		return url
	}
	if cfg.Version == "v0" {
		if runtime.GOARCH == "arm64" {
			return decodeB64(DL_NZ_ARM_V0)
		}
		return decodeB64(DL_NZ_AMD_V0)
	}
	if runtime.GOARCH == "arm64" {
		return decodeB64(DL_NZ_ARM_V1)
	}
	return decodeB64(DL_NZ_AMD_V1)
}

func installNezha() error {
	cfg := GlobalConfig.Tools["nezha"]
	url := resolveNezhaDownloadURL(cfg)
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("nezha", "bin"))
	os.MkdirAll(filepath.Dir(binPath), 0755)
	if err := downloadFile(url, binPath); err != nil {
		return err
	}
	return os.Chmod(binPath, 0755)
}

func installGost() error {
	url := decodeB64(DL_GS_AMD)
	if runtime.GOARCH == "arm64" {
		url = decodeB64(DL_GS_ARM)
	}
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("gost", "bin"))
	os.MkdirAll(filepath.Dir(binPath), 0755)
	if err := downloadFile(url, binPath); err != nil {
		return err
	}
	return os.Chmod(binPath, 0755)
}

func installKomari() error {
	arch := runtime.GOARCH
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = decodeB64(DL_KM_WIN)
	} else if runtime.GOOS == "darwin" {
		suffix = decodeB64(DL_KM_MAC)
	} else {
		s := "amd64"
		if arch == "arm64" {
			s = "arm64"
		}
		suffix = decodeB64(DL_KM_LIN) + s
	}
	url := decodeB64(DL_KM) + decodeB64(DL_KM_PRE) + suffix
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("komari", "bin")+ext)
	os.MkdirAll(filepath.Dir(binPath), 0755)
	if err := downloadFile(url, binPath); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(binPath, 0755)
	}
	return nil
}

func genShareLinks(cfg ToolCfg) []ShareLink {
	links := []ShareLink{}
	port := cfg.Port
	if port == 0 {
		port = 8001
	}
	uuid := cfg.UUID
	password := cfg.Key

	// 1. Base Domain (from CF Tunnel or fallback)
	cfCfg := GlobalConfig.Tools["cf-tunnel"]
	baseDomain := cfCfg.Domain
	if baseDomain == "" {
		if cfCfg.TunnelUrl != "" {
			baseDomain = cfCfg.TunnelUrl
		} else {
			if cfg.PublicIp != "" {
				baseDomain = cfg.PublicIp
			} else {
				baseDomain = "your-domain.com"
			}
		}
	}

	// 2. Connection Address Priority: Preference > Public IP > Base Domain
	connectAddr := cfg.PreferredDomain
	if connectAddr == "" {
		if cfg.PublicIp != "" {
			connectAddr = cfg.PublicIp
		} else {
			connectAddr = baseDomain
		}
	}

	// 3. SNI/Host Priority: Preference > Base Domain
	sni := cfg.PreferredDomain
	if sni == "" {
		sni = baseDomain
	}

	nodeName := "Node"
	if cfg.NodeName != "" {
		nodeName = cfg.NodeName
	}
	if cfg.ISPInfo != "" {
		nodeName += "-" + cfg.ISPInfo
	}

	wsEnabled := false
	if p, ok := cfg.Protocols["p0"]; ok && p.Enabled {
		wsEnabled = true
	}
	if p, ok := cfg.Protocols["p1"]; ok && p.Enabled {
		wsEnabled = true
	}
	if p, ok := cfg.Protocols["p2"]; ok && p.Enabled {
		wsEnabled = true
	}

	if p, ok := cfg.Protocols["p0"]; ok && p.Enabled {
		path := p.WsPath
		if path == "" {
			path = "/p0"
		}
		link := fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s#%s",
			uuid, connectAddr, sni, sni, strings.ReplaceAll(path, "/", "%2F"), nodeName)
		links = append(links, ShareLink{"VLESS", "vless", link})
	}

	if p, ok := cfg.Protocols["p1"]; ok && p.Enabled {
		path := p.WsPath
		if path == "" {
			path = "/p1"
		}
		// VMess uses 'add' for connection address, 'host'/'sni' for domain
		vmessCfg := map[string]interface{}{
			"v": "2", "ps": nodeName, "add": connectAddr, "port": "443", "id": uuid, "aid": "0", "scy": "none",
			"net": "ws", "type": "none", "host": sni, "path": path, "tls": "tls", "sni": sni, "alpn": "", "fp": "chrome",
		}
		data, _ := json.Marshal(vmessCfg)
		link := "vmess://" + base64.StdEncoding.EncodeToString(data)
		links = append(links, ShareLink{"VMess", "vmess", link})
	}

	if p, ok := cfg.Protocols["p2"]; ok && p.Enabled {
		path := p.WsPath
		if path == "" {
			path = "/p2"
		}
		link := fmt.Sprintf("trojan://%s@%s:443?security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s#%s",
			password, connectAddr, sni, sni, strings.ReplaceAll(path, "/", "%2F"), nodeName)
		links = append(links, ShareLink{"Trojan", "trojan", link})
	}

	if p, ok := cfg.Protocols["p3"]; ok && p.Enabled {
		socksPort := p.Port
		if socksPort == 0 {
			if wsEnabled {
				socksPort = port + 3
			} else {
				socksPort = port
			}
		}
		// SOCKS5 connects directly to IP/Domain
		link := fmt.Sprintf("socks5://%s:%s@%s:%d#%s", uuid, password, connectAddr, socksPort, nodeName)
		links = append(links, ShareLink{"SOCKS5", "socks", link})
	}

	if cfg.P4.Enabled && cfg.P4.Port != 0 {
		// Hysteria2 connects directly
		link := fmt.Sprintf("hysteria2://%s@%s:%d/?insecure=true&sni=%s#%s",
			password, connectAddr, cfg.P4.Port, sni, nodeName)
		links = append(links, ShareLink{"Hysteria2", "hysteria2", link})
	}

	if cfg.P5.Enabled && cfg.P5.Port != 0 {
		// TUIC connects directly
		link := fmt.Sprintf("tuic://%s:%s@%s:%d/?congestion_control=bbr&alpn=h3&allow_insecure=1&sni=%s#%s",
			uuid, password, connectAddr, cfg.P5.Port, sni, nodeName)
		links = append(links, ShareLink{"TUIC", "tuic", link})
	}

	return links
}
func startNezha() error {
	cfg := GlobalConfig.Tools["nezha"]
	cfg.DisableAutoUpdate = true
	GlobalConfig.Tools["nezha"] = cfg
	saveConfig()
	if cfg.Version == "" {
		cfg.Version = "v1"
		GlobalConfig.Tools["nezha"] = cfg
		saveConfig()
	}
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("nezha", "bin"))
	if cfg.Server == "" || cfg.Key == "" {
		return fmt.Errorf("nezha server or key missing")
	}
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		if err := installNezha(); err != nil {
			return err
		}
	}
	if cfg.UUID == "" {
		cfg.UUID = genRandomString(16)
		GlobalConfig.Tools["nezha"] = cfg
		saveConfig()
	}

	if cfg.Version == "v1" {
		server := cfg.Server
		useTls := true
		if strings.HasPrefix(server, "http://") {
			server = strings.TrimPrefix(server, "http://")
			useTls = false
		} else if strings.HasPrefix(server, "https://") {
			server = strings.TrimPrefix(server, "https://")
			useTls = true
		}
		if !strings.Contains(server, ":") {
			if useTls {
				server += ":443"
			} else {
				server += ":80"
			}
		}

		// Manual YAML construction to avoid dependency
		yamlContent := fmt.Sprintf(`client_secret: "%s"
debug: true
disable_auto_update: %t
disable_command_execute: %t
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: %t
insecure_tls: %t
ip_report_period: 1800
report_delay: 1
self_update_period: 0
server: "%s"
skip_connection_count: false
skip_procs_count: false
temperature: %t
tls: %t
use_gitee_to_upgrade: false
use_ipv6_country_code: %t
uuid: %s
`, cfg.Key, cfg.DisableAutoUpdate, cfg.DisableCommandExecute, cfg.Gpu, cfg.Insecure, server, cfg.Temperature, useTls, cfg.UseIPv6, cfg.UUID)

		cfgPath := filepath.Join(getTmpDir(), getRandomFileName("nezha-v1", "cfg")+".yaml")
		if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
			return err
		}
		err := startToolProcess("nezha", binPath, []string{"-c", cfgPath})
		if err != nil {
			logEvent("tool", "error", "[nezha] 启动失败: "+err.Error())
			if cfg.AutoDelete {
				os.Remove(binPath)
			}
			return err
		}
		cleanupTmpFile(cfgPath)
		cfg.Enabled = true
		GlobalConfig.Tools["nezha"] = cfg
		saveConfig()
		logEvent("tool", "info", "[nezha] 已启动")
		logEvent("probe", "info", "[nezha] 已启动")
		if cfg.AutoDelete {
			scheduleAutoDelete("nezha", func() {
				os.Remove(binPath)
			})
		}
		return nil
	}

	// V0 logic
	params := []string{"-s", cfg.Server, "-p", cfg.Key}
	if cfg.Tls {
		params = append(params, "--tls")
	}
	err := startToolProcess("nezha", binPath, params)
	if err != nil {
		logEvent("tool", "error", "[nezha] 启动失败: "+err.Error())
		if cfg.AutoDelete {
			os.Remove(binPath)
		}
		return err
	}
	cfg.Enabled = true
	GlobalConfig.Tools["nezha"] = cfg
	saveConfig()
	logEvent("tool", "info", "[nezha] 已启动")
	logEvent("probe", "info", "[nezha] 已启动")
	if cfg.AutoDelete {
		scheduleAutoDelete("nezha", func() {
			os.Remove(binPath)
		})
	}
	return nil
}

func startKomari() error {
	cfg := GlobalConfig.Tools["komari"]
	cfg.DisableAutoUpdate = true
	GlobalConfig.Tools["komari"] = cfg
	saveConfig()
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("komari", "bin"))
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		if err := installKomari(); err != nil {
			return err
		}
	}
	if cfg.Server == "" || cfg.Key == "" {
		return fmt.Errorf("komari server or key missing")
	}

	// Komari config generation
	kmCfg := map[string]interface{}{
		"endpoint":            cfg.Server,
		"token":               cfg.Key,
		"ignore_unsafe_cert":  cfg.Insecure,
		"gpu":                 cfg.Gpu,
		"disable_auto_update": cfg.DisableAutoUpdate,
	}

	// Write plain config to DataDir tmp (avoid /tmp issues in containers)
	plainPath := filepath.Join(getTmpDir(), getRandomFileName("komari-plain", "cfg")+".json")
	data, _ := json.MarshalIndent(kmCfg, "", "  ")
	if err := os.WriteFile(plainPath, data, 0644); err != nil {
		return err
	}

	err := startToolProcess("komari", binPath, []string{"--config", plainPath})
	if err != nil {
		logEvent("tool", "error", "[komari] 启动失败: "+err.Error())
		if cfg.AutoDelete {
			os.Remove(binPath)
		}
		return err
	}
	cleanupTmpFile(plainPath)
	cfg.Enabled = true
	GlobalConfig.Tools["komari"] = cfg
	saveConfig()
	logEvent("tool", "info", "[komari] 已启动")
	logEvent("probe", "info", "[komari] 已启动")
	if cfg.AutoDelete {
		scheduleAutoDelete("komari", func() {
			os.Remove(binPath)
		})
	}
	return nil
}

// Gost Tool
func startGost() error {
	cfg := GlobalConfig.Tools["gost"]
	binPath := filepath.Join(DataDir, "bin", getRandomFileName("gost", "bin"))
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		url := decodeB64(DL_GS_AMD)
		if runtime.GOARCH == "arm64" {
			url = decodeB64(DL_GS_ARM)
		}
		os.MkdirAll(filepath.Dir(binPath), 0755)
		if err := downloadFile(url, binPath); err != nil {
			return err
		}
		os.Chmod(binPath, 0755)
	}
	if cfg.Auth == "" {
		raw := genRandomString(32)
		cfg.Auth = raw[:8] + ":" + raw
		GlobalConfig.Tools["gost"] = cfg
		saveConfig()
		logEvent("tool", "info", "[gost] Auth: "+cfg.Auth)
	}
	args := []string{}
	if cfg.Mode != "tunnel" {
		return fmt.Errorf("gost mode disabled: %s", cfg.Mode)
	}
	if cfg.RemoteServer == "" || cfg.ExposedPort == 0 {
		return fmt.Errorf("gost tunnel config error")
	}
	authPart := ""
	if cfg.Auth != "" {
		authPart = cfg.Auth + "@"
	}
	if cfg.TunnelMultiplex {
		internalPort := GlobalConfig.WebPort
		if internalPort == 0 {
			internalPort = WebPort
		}
		multiplexPort := findAvailablePort(32001, 33000)
		if multiplexPort == 0 {
			multiplexPort = 32001
		}
		args = []string{
			"-L", fmt.Sprintf("auto://%s:%d/127.0.0.1:%d", authPart, multiplexPort, internalPort),
			"-L", fmt.Sprintf("rtcp://:%d/127.0.0.1:%d", cfg.ExposedPort, multiplexPort),
			"-F", fmt.Sprintf("relay+tls://%s%s", authPart, cfg.RemoteServer),
		}
	} else {
		localAddr := cfg.LocalAddr
		if localAddr == "" {
			localAddr = "127.0.0.1:80"
		}
		args = []string{
			"-L", fmt.Sprintf("rtcp://:%d/%s", cfg.ExposedPort, localAddr),
			"-F", fmt.Sprintf("relay+tls://%s%s", authPart, cfg.RemoteServer),
		}
	}
	err := startToolProcess("gost", binPath, args)
	if err != nil {
		logEvent("tool", "error", "[gost] 启动失败: "+err.Error())
		if cfg.AutoDelete {
			os.Remove(binPath)
		}
		return err
	}
	cfg.Enabled = true
	GlobalConfig.Tools["gost"] = cfg
	saveConfig()
	logEvent("tool", "info", "[gost] 已启动")
	if cfg.AutoDelete {
		scheduleAutoDelete("gost", func() {
			os.Remove(binPath)
		})
	}
	return nil
}

// Traffic Splitter
func startTrafficSplit(pubPort, webPort, proxyPort int) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", pubPort))
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSplit(conn, webPort, proxyPort)
	}
}

func findAvailablePort(startPort, endPort int) int {
	if startPort <= 0 {
		startPort = 10000
	}
	if endPort <= 0 {
		endPort = 65535
	}
	for port := startPort; port <= endPort; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			continue
		}
		ln.Close()
		return port
	}
	return 0
}

func cleanupOrphans() {
	logEvent("tool", "info", "正在清理残留进程...")
	for key, filename := range fileMap {
		if strings.Contains(key, "bin") && filename != "" {
			if runtime.GOOS == "windows" {
				_ = exec.Command("cmd", "/C", "taskkill /F /IM "+filename+".exe").Run()
			} else {
				_ = exec.Command("sh", "-c", "pkill -f "+filename).Run()
			}
		}
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/C", "timeout /t 1 >nul").Run()
	} else {
		_ = exec.Command("sh", "-c", "sleep 1").Run()
	}
}

func handleSplit(client net.Conn, webPort, proxyPort int) {
	defer client.Close()
	buffer := make([]byte, 1024)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(buffer)
	client.SetReadDeadline(time.Time{})
	targetPort := proxyPort
	if n > 0 {
		isHTTP := false
		methods := []string{"GET ", "POST", "HEAD", "PUT ", "DELE", "CONN", "OPTI"}
		headStr := string(buffer[:n])
		for _, m := range methods {
			if strings.HasPrefix(headStr, m) {
				isHTTP = true
				break
			}
		}
		if isHTTP || buffer[0] == 0x16 {
			targetPort = webPort
		}
	}
	target, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		return
	}
	defer target.Close()
	if n > 0 {
		target.Write(buffer[:n])
	}
	go io.Copy(target, client)
	io.Copy(client, target)
}

// Auth Middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := ""
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" || token != GlobalConfig.Token {
			http.Error(w, `{"error":"未授权"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func getArchInfo() ArchInfo {
	return ArchInfo{
		Platform: runtime.GOOS,
		ArchName: runtime.GOARCH,
	}
}

func setupAPIRoutes() {
	externRoot := getExternRoot()
	sendJSONError := func(w http.ResponseWriter, msg string, code int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": msg})
	}
	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         true,
			"dataDir":    DataDir,
			"configPath": ConfigPath,
			"webPort":    GlobalConfig.WebPort,
			"publicPort": GlobalConfig.Port,
			"arch":       getArchInfo(),
		})
	})
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		logEvent("api", "info", "[login]")
		if req.Username == GlobalConfig.Auth.Username && req.Password == GlobalConfig.Auth.Password {
			GlobalConfig.Token = fmt.Sprintf("tk_%d", time.Now().Unix())
			saveConfig()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "token": GlobalConfig.Token})
		} else {
			sendJSONError(w, "用户名或密码错误", http.StatusForbidden)
		}
	})

	http.HandleFunc("/api/auth/check", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	http.HandleFunc("/api/files/list", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "" {
			path = externRoot
		}
		logEvent("api", "info", "[files/list] "+path)
		fullPath := path
		if !filepath.IsAbs(path) {
			fullPath = filepath.Join(externRoot, path)
		}
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var items []FileItem
		for _, entry := range entries {
			info, _ := entry.Info()
			mtime := ""
			if info != nil {
				mtime = info.ModTime().Format(time.RFC3339)
			}
			items = append(items, FileItem{Name: entry.Name(), IsDirectory: entry.IsDir(), Size: info.Size(), Mtime: mtime})
		}
		parentDir := filepath.Dir(path)
		if parentDir == "." {
			parentDir = ""
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"items": items, "parentDir": parentDir})
	}))

	http.HandleFunc("/api/files/read", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		logEvent("api", "info", "[files/read] "+body.Path)
		fullPath := body.Path
		if !filepath.IsAbs(body.Path) {
			fullPath = filepath.Join(externRoot, body.Path)
		}
		content, err := os.ReadFile(fullPath)
		if err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "content": string(content)})
	}))

	http.HandleFunc("/api/files/save", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		logEvent("api", "info", "[files/save] "+body.Path)
		fullPath := body.Path
		if !filepath.IsAbs(body.Path) {
			fullPath = filepath.Join(externRoot, body.Path)
		}
		if err := os.WriteFile(fullPath, []byte(body.Content), 0644); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	http.HandleFunc("/api/files/delete", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		logEvent("api", "info", "[files/delete] "+body.Path)
		fullPath := body.Path
		if !filepath.IsAbs(body.Path) {
			fullPath = filepath.Join(externRoot, body.Path)
		}
		if err := os.RemoveAll(fullPath); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	http.HandleFunc("/api/files/rename", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			OldPath string `json:"oldPath"`
			NewPath string `json:"newPath"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		logEvent("api", "info", "[files/rename] "+body.OldPath+" -> "+body.NewPath)
		oldPath := body.OldPath
		newPath := body.NewPath
		if !filepath.IsAbs(body.OldPath) {
			oldPath = filepath.Join(externRoot, body.OldPath)
		}
		if !filepath.IsAbs(body.NewPath) {
			newPath = filepath.Join(externRoot, body.NewPath)
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	http.HandleFunc("/api/files/create", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		logEvent("api", "info", "[files/create] "+body.Type+" "+body.Path)
		fullPath := body.Path
		if !filepath.IsAbs(body.Path) {
			fullPath = filepath.Join(externRoot, body.Path)
		}
		if body.Type == "directory" {
			if err := os.MkdirAll(fullPath, 0755); err != nil {
				sendJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			if err := os.WriteFile(fullPath, []byte(""), 0644); err != nil {
				sendJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	http.HandleFunc("/api/auth/update", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		logEvent("api", "info", "[auth/update]")
		if body.Username != "" {
			GlobalConfig.Auth.Username = body.Username
		}
		if body.Password != "" {
			GlobalConfig.Auth.Password = body.Password
		}
		saveConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	http.HandleFunc("/api/system/config", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		logEvent("api", "info", "[system/config]")
		if v, ok := body["webPort"]; ok {
			switch val := v.(type) {
			case float64:
				GlobalConfig.WebPort = int(val)
			case string:
				if n, err := strconv.Atoi(val); err == nil {
					GlobalConfig.WebPort = n
				}
			}
		}
		if GlobalConfig.WebPort == 0 {
			GlobalConfig.WebPort = WebPort
		}
		saveConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	http.HandleFunc("/api/logs/config", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var cfg LogConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			sendJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		GlobalConfig.Logs.Enabled = cfg.Enabled
		GlobalConfig.Logs.LogTools = cfg.LogTools
		GlobalConfig.Logs.LogBots = cfg.LogBots
		GlobalConfig.Logs.LogApi = cfg.LogApi
		GlobalConfig.Logs.LogProbe = cfg.LogProbe
		GlobalConfig.Logs.MaxLines = cfg.MaxLines
		if GlobalConfig.Logs.MaxLines == 0 {
			GlobalConfig.Logs.MaxLines = 500
		}
		if GlobalConfig.Logs.LogProbe {
			logEvent("probe", "info", "[probe] 探针日志已启用")
		} else {
			logEvent("tool", "info", "[probe] 探针日志已关闭")
		}
		saveConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))

	// Tools API
	http.HandleFunc("/api/tools", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		logEvent("api", "info", "[tools]")
		status := make(map[string]interface{})
		names := []string{"cf-tunnel", "sing-box", "nezha", "komari", "gost"}
		for _, name := range names {
			running := false
			pidMu.Lock()
			if _, ok := pids[name]; ok {
				running = true
			}
			pidMu.Unlock()
			cfg, ok := GlobalConfig.Tools[name]
			if !ok {
				cfg = ToolCfg{Enabled: false}
			}

			var shareLinks []ShareLink
			var collection string
			if name == "sing-box" {
				shareLinks = genShareLinks(cfg)
				var linksText []string
				for _, l := range shareLinks {
					linksText = append(linksText, l.Link)
				}
				collection = base64.StdEncoding.EncodeToString([]byte(strings.Join(linksText, "\n")))
			}

			status[name] = map[string]interface{}{
				"running":    running,
				"installed":  isInstalled(name),
				"config":     cfg,
				"shareLinks": shareLinks,
				"collection": collection,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"tools":   status,
			"logs":    GlobalConfig.Logs,
			"arch":    getArchInfo(),
			"webPort": GlobalConfig.WebPort,
		})
	}))

	http.HandleFunc("/api/tools/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/tools/"), "/")
		if len(parts) < 2 {
			sendJSONError(w, "Invalid route", 404)
			return
		}
		name, action := parts[0], parts[1]
		if action == "config" {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				sendJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(bodyBytes, &raw); err != nil {
				sendJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			var body ToolCfg
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				sendJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			if GlobalConfig.Tools == nil {
				GlobalConfig.Tools = make(map[string]ToolCfg)
			}
			current := GlobalConfig.Tools[name]
			merged := mergeToolCfgWithRaw(current, body, raw)
			if name == "nezha" || name == "komari" {
				merged.DisableAutoUpdate = true
			}
			GlobalConfig.Tools[name] = merged
			saveConfig()
			logEvent("api", "info", "[tools/config] "+name)
		} else {
			var err error
			switch action {
			case "start":
				switch name {
				case "cf-tunnel":
					err = startCf()
				case "sing-box":
					err = startSingBox()
				case "nezha":
					err = startNezha()
				case "komari":
					err = startKomari()
				case "gost":
					err = startGost()
				}
			case "stop":
				stopToolProcess(name)
				if cfg, ok := GlobalConfig.Tools[name]; ok {
					cfg.Enabled = false
					GlobalConfig.Tools[name] = cfg
					saveConfig()
				}
				logEvent("tool", "info", "["+name+"] 已停止")
				if name == "nezha" || name == "komari" {
					logEvent("probe", "info", "["+name+"] 已停止")
				}
			case "restart":
				stopToolProcess(name)
				time.Sleep(500 * time.Millisecond)
				switch name {
				case "cf-tunnel":
					err = startCf()
				case "sing-box":
					err = startSingBox()
				case "nezha":
					err = startNezha()
				case "komari":
					err = startKomari()
				case "gost":
					err = startGost()
				}
			case "install":
				switch name {
				case "cf-tunnel":
					err = installCf()
				case "sing-box":
					if err := installSingBox(); err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
				case "nezha":
					if err := installNezha(); err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
				case "komari":
					if err := installKomari(); err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
				case "gost":
					if err := installGost(); err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
				}
			case "deleteBin":
				binName := getRandomFileName(name, "bin")
				os.Remove(filepath.Join(DataDir, "bin", binName))
				delete(fileMap, "bin:"+name)
				saveFileMap()
				if name == "sing-box" || name == "cf-tunnel" {
					deleteCerts()
				}
			case "delete":
				binName := getRandomFileName(name, "bin")
				os.Remove(filepath.Join(DataDir, "bin", binName))
				delete(fileMap, "bin:"+name)
				saveFileMap()
				if name == "cf-tunnel" || name == "sing-box" {
					deleteCerts()
				}
				logEvent("tool", "info", "["+name+"] 已删除")
			}
			if err != nil {
				sendJSONError(w, err.Error(), 500)
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))

	http.HandleFunc("/api/logs/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/logs/")
		if cb, ok := logBuffers[name]; ok {
			lines := cb.GetLines()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "logs": strings.Join(lines, "\n")})
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "logs": ""})
		}
	}))

	http.HandleFunc("/api/logs", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		logEvent("api", "info", "[logs]")
		logMu.Lock()
		res := make([]LogEntry, len(logs))
		copy(res, logs)
		logMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "logs": res})
	}))
}

func main() {
	initPaths()
	logEvent("tool", "info", "DataDir: "+DataDir)
	if err := loadConfig(); err != nil {
		log.Printf("Err: %v", err)
	}
	logEvent("tool", "info", "ConfigPath: "+ConfigPath)
	loadFileMap()
	setupAPIRoutes()

	webPort := GlobalConfig.WebPort
	if webPort == 0 {
		webPort = WebPort
	}
	publicPort := 0
	if envPort := os.Getenv("PORT"); envPort != "" {
		if v, err := strconv.Atoi(envPort); err == nil {
			publicPort = v
		}
	}
	if envPort := os.Getenv("SERVER_PORT"); envPort != "" && publicPort == 0 {
		if v, err := strconv.Atoi(envPort); err == nil {
			publicPort = v
		}
	}
	if envPort := os.Getenv("PRIMARY_PORT"); envPort != "" && publicPort == 0 {
		if v, err := strconv.Atoi(envPort); err == nil {
			publicPort = v
		}
	}
	if publicPort == 0 {
		publicPort = GlobalConfig.Port
	}
	if publicPort == 0 {
		publicPort = DefaultPubPort
	}

	go startTrafficSplit(publicPort, webPort, ProxyPort)
	cleanupOrphans()
	logEvent("tool", "info", fmt.Sprintf("Server: 127.0.0.1:%d", webPort))
	logEvent("tool", "info", fmt.Sprintf("Splitter: %d -> %d/%d", publicPort, webPort, ProxyPort))
	logEvent("tool", "info", "AutoStart scan begin")

	go func() {
		time.Sleep(1 * time.Second)
		names := []string{"cf-tunnel", "sing-box", "nezha", "komari", "gost"}
		for _, name := range names {
			cfg, ok := GlobalConfig.Tools[name]
			if !ok || !cfg.AutoStart {
				continue
			}
			logEvent("tool", "info", "[autoStart] "+name+" enabled")
			go func(toolName string) {
				retries := 3
				for {
					var err error
					switch toolName {
					case "cf-tunnel":
						err = startCf()
					case "sing-box":
						err = startSingBox()
					case "nezha":
						err = startNezha()
					case "komari":
						err = startKomari()
					case "gost":
						err = startGost()
					}
					if err == nil {
						return
					}
					logEvent("tool", "error", "["+toolName+"] 启动失败: "+err.Error())
					retries--
					if retries < 0 {
						return
					}
					time.Sleep(2 * time.Second)
				}
			}(name)
		}
		logEvent("tool", "info", "AutoStart scan end")
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		// 1. Try serving from local "public" directory
		localPath := filepath.Join("public", path)
		info, err := os.Stat(localPath)
		if err == nil && !info.IsDir() {
			http.ServeFile(w, r, localPath)
			return
		}

		// 2. If requesting root/index.html and local not found, serve embedded monolithic HTML
		if path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(indexHTML))
			return
		}

		// 3. 404
		http.NotFound(w, r)
	})

	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		tmpl, _ := template.New("admin").Parse(adminHTML)
		data := map[string]interface{}{
			"Root": "/", "PathSep": string(os.PathSeparator),
			"CK_t0": "cf-tunnel", "CK_t1": "sing-box", "CK_t2": "nezha", "CK_t3": "komari", "CK_t4": "gost",
			"UI_t0": "Cloudflared", "UI_t1": "Sing-box", "UI_t2": "Nezha", "UI_t3": "Komari", "UI_t4": "Gost",
			"PN_d0": "VLESS", "PN_d1": "VMess", "PN_d2": "Trojan", "PN_d3": "SOCKS", "PN_d4": "Hysteria2", "PN_d5": "TUIC",
		}
		tmpl.Execute(w, data)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", webPort), nil))
}
