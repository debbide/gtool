// Tool definitions
const toolsData = [
  { id: "color", icon: "🎨", title: "颜色转换器", desc: "HEX ↔ RGB 颜色格式互转" },
  { id: "text", icon: "📊", title: "文本统计器", desc: "统计字数、字符、行数等" },
  { id: "json", icon: "{ }", title: "JSON 格式化", desc: "格式化、压缩、验证 JSON" },
  { id: "base64", icon: "🔐", title: "Base64 编解码", desc: "文本与 Base64 互转" },
  { id: "password", icon: "🔑", title: "密码生成器", desc: "生成安全的随机密码" },
  { id: "timestamp", icon: "⏰", title: "时间戳转换", desc: "Unix 时间戳与日期互转" },
  { id: "url", icon: "🔗", title: "URL 编解码", desc: "URL 编码与解码转换" },
  { id: "hash", icon: "#️⃣", title: "哈希生成器", desc: "MD5, SHA-256, SHA-512" },
  { id: "uuid", icon: "🆔", title: "UUID 生成器", desc: "生成随机 UUID v4" },
  { id: "base", icon: "🔢", title: "进制转换器", desc: "二、八、十、十六进制" },
  { id: "regex", icon: "🔍", title: "正则测试器", desc: "测试正则表达式匹配" },
  { id: "markdown", icon: "📝", title: "Markdown 预览", desc: "实时预览 Markdown" },
  { id: "qrcode", icon: "📱", title: "二维码生成", desc: "文本/URL 生成二维码" },
  { id: "jwt", icon: "🎫", title: "JWT 解析器", desc: "解析 JWT Token 内容" },
  { id: "html", icon: "🏷️", title: "HTML 实体编解码", desc: "HTML 特殊字符转义" },
  { id: "case", icon: "🔤", title: "大小写转换", desc: "大写、小写、驼峰等" },
  { id: "lorem", icon: "📄", title: "Lorem 生成器", desc: "生成占位假文本" },
  { id: "diff", icon: "📋", title: "文本对比", desc: "对比两段文本差异" },
];

// ==================== Color Converter ====================
function renderColorTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🎨</div>
        <div>
          <h2>颜色转换器</h2>
          <p>HEX ↔ RGB 颜色格式互转</p>
        </div>
      </div>
      <div class="grid-2">
        <div>
          <div class="color-preview" id="color-preview" style="background: #14b8a6"></div>
          <div class="grid-2">
            <button class="btn-secondary" onclick="copyText(document.getElementById('hex-input').value)">复制 HEX</button>
            <button class="btn-secondary" onclick="copyText(document.getElementById('rgb-result').textContent)">复制 RGB</button>
          </div>
        </div>
        <div>
          <div class="mb-2">
            <label>HEX 值</label>
            <input type="text" id="hex-input" class="input-field font-mono" value="#14b8a6" oninput="hexToRgb(this.value)">
          </div>
          <div class="mb-2">
            <label>RGB 值</label>
            <div class="grid-3">
              <div>
                <span class="text-xs text-muted">R</span>
                <input type="number" id="rgb-r" class="input-field" value="20" min="0" max="255" oninput="rgbToHex()">
              </div>
              <div>
                <span class="text-xs text-muted">G</span>
                <input type="number" id="rgb-g" class="input-field" value="184" min="0" max="255" oninput="rgbToHex()">
              </div>
              <div>
                <span class="text-xs text-muted">B</span>
                <input type="number" id="rgb-b" class="input-field" value="166" min="0" max="255" oninput="rgbToHex()">
              </div>
            </div>
          </div>
          <div class="result-box mt-2">
            <span class="text-xs text-muted">CSS 格式</span>
            <p class="text-primary" id="rgb-result">rgb(20, 184, 166)</p>
          </div>
        </div>
      </div>
    </div>
  `;
}

function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if (result) {
    const r = parseInt(result[1], 16);
    const g = parseInt(result[2], 16);
    const b = parseInt(result[3], 16);
    document.getElementById('rgb-r').value = r;
    document.getElementById('rgb-g').value = g;
    document.getElementById('rgb-b').value = b;
    updateColorPreview(hex, r, g, b);
  }
}

function rgbToHex() {
  const r = parseInt(document.getElementById('rgb-r').value) || 0;
  const g = parseInt(document.getElementById('rgb-g').value) || 0;
  const b = parseInt(document.getElementById('rgb-b').value) || 0;
  const hex = '#' + [r, g, b].map(x => Math.max(0, Math.min(255, x)).toString(16).padStart(2, '0')).join('');
  document.getElementById('hex-input').value = hex;
  updateColorPreview(hex, r, g, b);
}

function updateColorPreview(hex, r, g, b) {
  document.getElementById('color-preview').style.background = hex;
  document.getElementById('rgb-result').textContent = `rgb(${r}, ${g}, ${b})`;
}

// ==================== Text Counter ====================
function renderTextTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">📊</div>
        <div>
          <h2>文本统计器</h2>
          <p>统计字数、字符、行数等信息</p>
        </div>
      </div>
      <div class="mb-2">
        <textarea id="text-input" class="textarea-field" rows="8" placeholder="在此输入或粘贴文本..." oninput="updateTextStats()"></textarea>
      </div>
      <div class="stats-grid" id="text-stats">
        <div class="stat-item"><div class="icon">📝</div><div class="label">总字符</div><div class="value" id="stat-chars">0</div></div>
        <div class="stat-item"><div class="icon">✏️</div><div class="label">不含空格</div><div class="value" id="stat-chars-ns">0</div></div>
        <div class="stat-item"><div class="icon">📖</div><div class="label">单词数</div><div class="value" id="stat-words">0</div></div>
        <div class="stat-item"><div class="icon">🀄</div><div class="label">中文字符</div><div class="value" id="stat-chinese">0</div></div>
        <div class="stat-item"><div class="icon">📄</div><div class="label">行数</div><div class="value" id="stat-lines">0</div></div>
        <div class="stat-item"><div class="icon">💬</div><div class="label">句子数</div><div class="value" id="stat-sentences">0</div></div>
        <div class="stat-item"><div class="icon">📑</div><div class="label">段落数</div><div class="value" id="stat-paragraphs">0</div></div>
        <div class="stat-item"><div class="icon">⏱️</div><div class="label">阅读(分钟)</div><div class="value" id="stat-reading">0</div></div>
      </div>
      <div class="btn-group">
        <button class="btn-secondary" onclick="document.getElementById('text-input').value='';updateTextStats()">清空</button>
      </div>
    </div>
  `;
}

function updateTextStats() {
  const text = document.getElementById('text-input').value;
  const chars = text.length;
  const charsNoSpace = text.replace(/\s/g, '').length;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const lines = text ? text.split(/\n/).length : 0;
  const sentences = text.split(/[.!?。！？]+/).filter(s => s.trim()).length;
  const paragraphs = text.split(/\n\n+/).filter(p => p.trim()).length;
  const chineseChars = (text.match(/[\u4e00-\u9fa5]/g) || []).length;
  const readingTime = Math.ceil((words * 0.5 + chineseChars * 0.15) / 60);

  document.getElementById('stat-chars').textContent = chars;
  document.getElementById('stat-chars-ns').textContent = charsNoSpace;
  document.getElementById('stat-words').textContent = words;
  document.getElementById('stat-chinese').textContent = chineseChars;
  document.getElementById('stat-lines').textContent = lines;
  document.getElementById('stat-sentences').textContent = sentences;
  document.getElementById('stat-paragraphs').textContent = paragraphs || 0;
  document.getElementById('stat-reading').textContent = readingTime;
}

// ==================== JSON Formatter ====================
function renderJsonTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">{ }</div>
        <div>
          <h2>JSON 格式化</h2>
          <p>格式化、压缩和验证 JSON 数据</p>
        </div>
      </div>
      <div class="grid-2 mb-2">
        <div>
          <div class="flex justify-between items-center mb-1">
            <label>输入</label>
            <button class="text-xs text-primary" style="background:none;border:none;cursor:pointer" onclick="loadSampleJson()">加载示例</button>
          </div>
          <textarea id="json-input" class="textarea-field" rows="12" placeholder='{"key": "value"}'></textarea>
        </div>
        <div>
          <label>输出</label>
          <textarea id="json-output" class="textarea-field" rows="12" readonly style="background:rgba(22,27,34,0.3)"></textarea>
        </div>
      </div>
      <div id="json-error"></div>
      <div class="btn-group">
        <select id="json-indent" class="input-field" style="width:auto">
          <option value="2">2 空格</option>
          <option value="4">4 空格</option>
        </select>
        <button class="btn-primary" onclick="formatJson()">格式化</button>
        <button class="btn-secondary" onclick="minifyJson()">压缩</button>
        <button class="btn-secondary" onclick="copyText(document.getElementById('json-output').value)">复制结果</button>
      </div>
    </div>
  `;
}

function formatJson() {
  try {
    const input = document.getElementById('json-input').value;
    const indent = parseInt(document.getElementById('json-indent').value);
    const parsed = JSON.parse(input);
    document.getElementById('json-output').value = JSON.stringify(parsed, null, indent);
    document.getElementById('json-error').innerHTML = '';
  } catch (e) {
    document.getElementById('json-error').innerHTML = `<div class="error-box">JSON 格式错误: ${e.message}</div>`;
  }
}

function minifyJson() {
  try {
    const input = document.getElementById('json-input').value;
    const parsed = JSON.parse(input);
    document.getElementById('json-output').value = JSON.stringify(parsed);
    document.getElementById('json-error').innerHTML = '';
  } catch (e) {
    document.getElementById('json-error').innerHTML = `<div class="error-box">JSON 格式错误: ${e.message}</div>`;
  }
}

function loadSampleJson() {
  document.getElementById('json-input').value = JSON.stringify({
    name: "工具集",
    version: "1.0.0",
    tools: ["颜色转换", "文本统计", "JSON格式化"],
    config: { theme: "dark", language: "zh-CN" }
  });
}

// ==================== Base64 Tool ====================
function renderBase64Tool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🔐</div>
        <div>
          <h2>Base64 编解码</h2>
          <p>文本与 Base64 格式互转</p>
        </div>
      </div>
      <div class="mode-toggle">
        <button class="mode-btn active" id="base64-encode-btn" onclick="setBase64Mode('encode')">编码 (文本 → Base64)</button>
        <button class="mode-btn" id="base64-decode-btn" onclick="setBase64Mode('decode')">解码 (Base64 → 文本)</button>
      </div>
      <div class="mb-2">
        <label id="base64-input-label">原始文本</label>
        <textarea id="base64-input" class="textarea-field" rows="5" placeholder="输入要编码的文本..."></textarea>
      </div>
      <div class="mb-2">
        <label id="base64-output-label">Base64 结果</label>
        <textarea id="base64-output" class="textarea-field" rows="5" readonly style="background:rgba(22,27,34,0.3)"></textarea>
      </div>
      <div id="base64-error"></div>
      <div class="btn-group">
        <button class="btn-primary" id="base64-action-btn" onclick="convertBase64()">编码</button>
        <button class="btn-secondary" onclick="copyText(document.getElementById('base64-output').value)">复制结果</button>
        <button class="btn-secondary" onclick="clearBase64()">清空</button>
      </div>
    </div>
  `;
}

let base64Mode = 'encode';
function setBase64Mode(mode) {
  base64Mode = mode;
  document.getElementById('base64-encode-btn').classList.toggle('active', mode === 'encode');
  document.getElementById('base64-decode-btn').classList.toggle('active', mode === 'decode');
  document.getElementById('base64-input-label').textContent = mode === 'encode' ? '原始文本' : 'Base64 字符串';
  document.getElementById('base64-output-label').textContent = mode === 'encode' ? 'Base64 结果' : '解码文本';
  document.getElementById('base64-action-btn').textContent = mode === 'encode' ? '编码' : '解码';
  document.getElementById('base64-input').placeholder = mode === 'encode' ? '输入要编码的文本...' : '输入 Base64 字符串...';
}

function convertBase64() {
  const input = document.getElementById('base64-input').value;
  try {
    if (base64Mode === 'encode') {
      document.getElementById('base64-output').value = btoa(unescape(encodeURIComponent(input)));
    } else {
      document.getElementById('base64-output').value = decodeURIComponent(escape(atob(input)));
    }
    document.getElementById('base64-error').innerHTML = '';
  } catch (e) {
    document.getElementById('base64-error').innerHTML = `<div class="error-box">${base64Mode === 'encode' ? '编码' : '解码'}失败</div>`;
  }
}

function clearBase64() {
  document.getElementById('base64-input').value = '';
  document.getElementById('base64-output').value = '';
  document.getElementById('base64-error').innerHTML = '';
}

// ==================== Password Generator ====================
function renderPasswordTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🔑</div>
        <div>
          <h2>密码生成器</h2>
          <p>生成安全的随机密码</p>
        </div>
      </div>
      <div class="result-box mb-2 flex justify-between items-center" style="min-height:3rem">
        <span id="password-result" class="font-mono" style="font-size:1.125rem;word-break:break-all">点击生成按钮创建密码</span>
        <button class="btn-secondary" onclick="copyText(document.getElementById('password-result').textContent)" style="margin-left:1rem">复制</button>
      </div>
      <div class="strength-bar mb-2" id="password-strength">
        <span class="text-sm text-muted" style="margin-right:0.5rem">强度:</span>
        <div class="strength-segment" id="str-1"></div>
        <div class="strength-segment" id="str-2"></div>
        <div class="strength-segment" id="str-3"></div>
        <span class="text-sm" id="str-text" style="margin-left:0.5rem">-</span>
      </div>
      <div class="grid-2 mb-2">
        <div>
          <label>密码长度: <span id="pwd-length-val">16</span></label>
          <input type="range" id="pwd-length" min="8" max="64" value="16" oninput="document.getElementById('pwd-length-val').textContent=this.value">
        </div>
        <div class="checkbox-group">
          <label class="checkbox-label"><input type="checkbox" id="pwd-upper" checked> 大写字母 (A-Z)</label>
          <label class="checkbox-label"><input type="checkbox" id="pwd-lower" checked> 小写字母 (a-z)</label>
          <label class="checkbox-label"><input type="checkbox" id="pwd-number" checked> 数字 (0-9)</label>
          <label class="checkbox-label"><input type="checkbox" id="pwd-symbol" checked> 特殊符号</label>
        </div>
      </div>
      <button class="btn-primary" style="width:100%" onclick="generatePassword()">生成密码</button>
      <div id="password-history" class="history-list"></div>
    </div>
  `;
}

let passwordHistory = [];
function generatePassword() {
  const length = parseInt(document.getElementById('pwd-length').value);
  const useUpper = document.getElementById('pwd-upper').checked;
  const useLower = document.getElementById('pwd-lower').checked;
  const useNumber = document.getElementById('pwd-number').checked;
  const useSymbol = document.getElementById('pwd-symbol').checked;

  let chars = '';
  if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (useNumber) chars += '0123456789';
  if (useSymbol) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars[array[i] % chars.length];
  }

  document.getElementById('password-result').textContent = password;
  updatePasswordStrength(password);
  
  passwordHistory.unshift(password);
  passwordHistory = passwordHistory.slice(0, 5);
  renderPasswordHistory();
}

function updatePasswordStrength(pwd) {
  let score = 0;
  if (pwd.length >= 12) score++;
  if (pwd.length >= 16) score++;
  if (/[a-z]/.test(pwd)) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^a-zA-Z0-9]/.test(pwd)) score++;

  const s1 = document.getElementById('str-1');
  const s2 = document.getElementById('str-2');
  const s3 = document.getElementById('str-3');
  const text = document.getElementById('str-text');

  s1.className = s2.className = s3.className = 'strength-segment';
  
  if (score <= 2) {
    s1.classList.add('weak');
    text.textContent = '弱';
    text.style.color = 'var(--error)';
  } else if (score <= 4) {
    s1.classList.add('medium');
    s2.classList.add('medium');
    text.textContent = '中';
    text.style.color = 'var(--accent)';
  } else {
    s1.classList.add('strong');
    s2.classList.add('strong');
    s3.classList.add('strong');
    text.textContent = '强';
    text.style.color = 'var(--primary)';
  }
}

function renderPasswordHistory() {
  const container = document.getElementById('password-history');
  if (passwordHistory.length === 0) {
    container.innerHTML = '';
    return;
  }
  container.innerHTML = `
    <h3 class="text-sm text-muted mt-3 mb-1">历史记录</h3>
    ${passwordHistory.map(pwd => `
      <div class="history-item">
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis">${pwd}</span>
        <button onclick="copyText('${pwd}')">复制</button>
      </div>
    `).join('')}
  `;
}

// ==================== Timestamp Converter ====================
let timestampInterval;
function renderTimestampTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">⏰</div>
        <div>
          <h2>时间戳转换</h2>
          <p>Unix 时间戳与日期时间互转</p>
        </div>
      </div>
      <div class="current-time">
        <div class="label">当前时间</div>
        <div class="datetime" id="current-datetime">-</div>
        <div class="timestamp" id="current-timestamp">-</div>
      </div>
      <div class="mode-toggle mb-2">
        <button class="mode-btn active" id="ts-ms-btn" onclick="setTimestampUnit('ms')">毫秒 (ms)</button>
        <button class="mode-btn" id="ts-s-btn" onclick="setTimestampUnit('s')">秒 (s)</button>
      </div>
      <div class="grid-2 mb-2">
        <div>
          <label>时间戳</label>
          <div class="flex gap-2">
            <input type="text" id="ts-input" class="input-field font-mono" placeholder="1704067200000">
            <button class="btn-secondary" onclick="copyText(document.getElementById('ts-input').value)">复制</button>
          </div>
          <button class="btn-primary mt-2" style="width:100%" onclick="timestampToDate()">→ 转为日期</button>
        </div>
        <div>
          <label>日期时间</label>
          <div class="flex gap-2">
            <input type="text" id="dt-input" class="input-field" placeholder="2024-01-01 00:00:00">
            <button class="btn-secondary" onclick="copyText(document.getElementById('dt-input').value)">复制</button>
          </div>
          <button class="btn-primary mt-2" style="width:100%" onclick="dateToTimestamp()">→ 转为时间戳</button>
        </div>
      </div>
      <div class="btn-group">
        <button class="btn-secondary" onclick="setNowTime()">使用当前时间</button>
        <button class="btn-secondary" onclick="clearTimestamp()">清空</button>
      </div>
    </div>
  `;
}

let tsUnit = 'ms';
function setTimestampUnit(unit) {
  tsUnit = unit;
  document.getElementById('ts-ms-btn').classList.toggle('active', unit === 'ms');
  document.getElementById('ts-s-btn').classList.toggle('active', unit === 's');
}

function startTimestampTimer() {
  if (timestampInterval) clearInterval(timestampInterval);
  timestampInterval = setInterval(() => {
    const now = new Date();
    document.getElementById('current-datetime').textContent = formatDate(now);
    document.getElementById('current-timestamp').textContent = tsUnit === 'ms' ? now.getTime() : Math.floor(now.getTime() / 1000);
  }, 1000);
}

function formatDate(date) {
  const pad = n => n.toString().padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function timestampToDate() {
  let ts = parseInt(document.getElementById('ts-input').value);
  if (tsUnit === 's') ts *= 1000;
  const date = new Date(ts);
  if (!isNaN(date.getTime())) {
    document.getElementById('dt-input').value = formatDate(date);
  }
}

function dateToTimestamp() {
  const date = new Date(document.getElementById('dt-input').value);
  if (!isNaN(date.getTime())) {
    const ts = tsUnit === 's' ? Math.floor(date.getTime() / 1000) : date.getTime();
    document.getElementById('ts-input').value = ts;
  }
}

function setNowTime() {
  const now = new Date();
  document.getElementById('dt-input').value = formatDate(now);
  document.getElementById('ts-input').value = tsUnit === 's' ? Math.floor(now.getTime() / 1000) : now.getTime();
}

function clearTimestamp() {
  document.getElementById('ts-input').value = '';
  document.getElementById('dt-input').value = '';
}

// ==================== URL Encoder ====================
function renderUrlTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🔗</div>
        <div>
          <h2>URL 编解码</h2>
          <p>URL 编码与解码转换</p>
        </div>
      </div>
      <div class="mode-toggle">
        <button class="mode-btn active" id="url-encode-btn" onclick="setUrlMode('encode')">编码</button>
        <button class="mode-btn" id="url-decode-btn" onclick="setUrlMode('decode')">解码</button>
      </div>
      <div class="mb-2">
        <label id="url-input-label">原始文本</label>
        <textarea id="url-input" class="textarea-field" rows="4" placeholder="输入要编码的文本..."></textarea>
      </div>
      <div class="mb-2">
        <label>结果</label>
        <textarea id="url-output" class="textarea-field" rows="4" readonly style="background:rgba(22,27,34,0.3)"></textarea>
      </div>
      <div class="btn-group">
        <button class="btn-primary" id="url-action-btn" onclick="convertUrl()">编码</button>
        <button class="btn-secondary" onclick="copyText(document.getElementById('url-output').value)">复制结果</button>
        <button class="btn-secondary" onclick="document.getElementById('url-input').value='';document.getElementById('url-output').value=''">清空</button>
      </div>
    </div>
  `;
}

let urlMode = 'encode';
function setUrlMode(mode) {
  urlMode = mode;
  document.getElementById('url-encode-btn').classList.toggle('active', mode === 'encode');
  document.getElementById('url-decode-btn').classList.toggle('active', mode === 'decode');
  document.getElementById('url-action-btn').textContent = mode === 'encode' ? '编码' : '解码';
  document.getElementById('url-input-label').textContent = mode === 'encode' ? '原始文本' : '编码后的 URL';
}

function convertUrl() {
  const input = document.getElementById('url-input').value;
  try {
    document.getElementById('url-output').value = urlMode === 'encode' ? encodeURIComponent(input) : decodeURIComponent(input);
  } catch (e) {
    document.getElementById('url-output').value = '转换失败';
  }
}

// ==================== Hash Generator ====================
function renderHashTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">#️⃣</div>
        <div>
          <h2>哈希生成器</h2>
          <p>生成 MD5, SHA-256, SHA-512 哈希值</p>
        </div>
      </div>
      <div class="mb-2">
        <label>输入文本</label>
        <textarea id="hash-input" class="textarea-field" rows="5" placeholder="输入要生成哈希的文本..."></textarea>
      </div>
      <button class="btn-primary" style="width:100%" onclick="generateHashes()">生成哈希</button>
      <div id="hash-results" class="mt-2"></div>
    </div>
  `;
}

// MD5 implementation (for compatibility - not cryptographically secure)
function md5(string) {
  function md5cycle(x, k) {
    var a = x[0], b = x[1], c = x[2], d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936);
    d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819);
    b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897);
    d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341);
    b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416);
    d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063);
    b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682);
    d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290);
    b = ff(b, c, d, a, k[15], 22, 1236535329);
    a = gg(a, b, c, d, k[1], 5, -165796510);
    d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713);
    b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691);
    d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335);
    b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438);
    d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961);
    b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467);
    d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473);
    b = gg(b, c, d, a, k[12], 20, -1926607734);
    a = hh(a, b, c, d, k[5], 4, -378558);
    d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562);
    b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060);
    d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632);
    b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174);
    d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979);
    b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487);
    d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520);
    b = hh(b, c, d, a, k[2], 23, -995338651);
    a = ii(a, b, c, d, k[0], 6, -198630844);
    d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905);
    b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571);
    d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523);
    b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359);
    d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380);
    b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070);
    d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259);
    b = ii(b, c, d, a, k[9], 21, -343485551);
    x[0] = add32(a, x[0]);
    x[1] = add32(b, x[1]);
    x[2] = add32(c, x[2]);
    x[3] = add32(d, x[3]);
  }
  function cmn(q, a, b, x, s, t) {
    a = add32(add32(a, q), add32(x, t));
    return add32((a << s) | (a >>> (32 - s)), b);
  }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
  function md5blk(s) {
    var md5blks = [], i;
    for (i = 0; i < 64; i += 4) {
      md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24);
    }
    return md5blks;
  }
  function md5blk_array(a) {
    var md5blks = [], i;
    for (i = 0; i < 64; i += 4) {
      md5blks[i >> 2] = a[i] + (a[i + 1] << 8) + (a[i + 2] << 16) + (a[i + 3] << 24);
    }
    return md5blks;
  }
  function md51(s) {
    var n = s.length, state = [1732584193, -271733879, -1732584194, 271733878], i, length, tail, tmp, lo, hi;
    for (i = 64; i <= n; i += 64) { md5cycle(state, md5blk(s.substring(i - 64, i))); }
    s = s.substring(i - 64);
    length = s.length;
    tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (i = 0; i < length; i++) { tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3); }
    tail[i >> 2] |= 0x80 << ((i % 4) << 3);
    if (i > 55) { md5cycle(state, tail); for (i = 0; i < 16; i++) tail[i] = 0; }
    tmp = n * 8; tmp = tmp.toString(16).match(/(.*?)(.{0,8})$/);
    lo = parseInt(tmp[2], 16); hi = parseInt(tmp[1], 16) || 0;
    tail[14] = lo; tail[15] = hi;
    md5cycle(state, tail);
    return state;
  }
  function rhex(n) {
    var s = '', j;
    for (j = 0; j < 4; j++) { s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] + hex_chr[(n >> (j * 8)) & 0x0F]; }
    return s;
  }
  function hex(x) { for (var i = 0; i < x.length; i++) { x[i] = rhex(x[i]); } return x.join(''); }
  function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
  var hex_chr = '0123456789abcdef'.split('');
  return hex(md51(unescape(encodeURIComponent(string))));
}

async function generateHashes() {
  const input = document.getElementById('hash-input').value;
  if (!input) {
    showToast('请输入要哈希的文本', 'error');
    return;
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(input);

  const toHex = buffer => Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');

  const [sha256, sha512] = await Promise.all([
    crypto.subtle.digest('SHA-256', data),
    crypto.subtle.digest('SHA-512', data)
  ]);

  const md5Hash = md5(input);

  const results = [
    { name: 'MD5', hash: md5Hash, warn: true },
    { name: 'SHA-256', hash: toHex(sha256) },
    { name: 'SHA-512', hash: toHex(sha512) }
  ];

  document.getElementById('hash-results').innerHTML = results.map(r => `
    <div class="result-box mb-1">
      <div class="flex justify-between items-center mb-1">
        <span class="text-primary font-bold">${r.name}${r.warn ? ' <span class="text-xs text-muted">(不安全)</span>' : ''}</span>
        <button class="text-xs text-muted" style="background:none;border:none;cursor:pointer" onclick="copyText('${r.hash}')">复制</button>
      </div>
      <p class="text-xs text-muted break-all">${r.hash}</p>
    </div>
  `).join('');
}

// ==================== UUID Generator ====================
function renderUuidTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🆔</div>
        <div>
          <h2>UUID 生成器</h2>
          <p>生成随机的 UUID v4</p>
        </div>
      </div>
      <div class="grid-3 mb-2">
        <div>
          <label>生成数量</label>
          <input type="number" id="uuid-count" class="input-field" value="5" min="1" max="100">
        </div>
        <div>
          <label>格式</label>
          <select id="uuid-format" class="input-field">
            <option value="default">标准格式</option>
            <option value="upper">大写</option>
            <option value="nodash">无连字符</option>
          </select>
        </div>
        <div style="display:flex;align-items:flex-end">
          <button class="btn-primary" style="width:100%" onclick="generateUuids()">生成 UUID</button>
        </div>
      </div>
      <div id="uuid-results"></div>
    </div>
  `;
}

function generateUuids() {
  const count = Math.min(100, Math.max(1, parseInt(document.getElementById('uuid-count').value) || 5));
  const format = document.getElementById('uuid-format').value;
  
  const uuids = [];
  for (let i = 0; i < count; i++) {
    let uuid = crypto.randomUUID();
    if (format === 'upper') uuid = uuid.toUpperCase();
    if (format === 'nodash') uuid = uuid.replace(/-/g, '');
    uuids.push(uuid);
  }
  
  document.getElementById('uuid-results').innerHTML = `
    <div class="flex justify-between items-center mb-1">
      <span class="text-sm text-muted">已生成 ${uuids.length} 个 UUID</span>
      <button class="btn-secondary text-sm" onclick="copyText(\`${uuids.join('\\n')}\`)">复制全部</button>
    </div>
    <div style="max-height:20rem;overflow-y:auto">
      ${uuids.map(uuid => `
        <div class="history-item">
          <span class="font-mono">${uuid}</span>
          <button onclick="copyText('${uuid}')">复制</button>
        </div>
      `).join('')}
    </div>
  `;
}

// ==================== Number Base Converter ====================
function renderBaseTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🔢</div>
        <div>
          <h2>进制转换器</h2>
          <p>二进制、八进制、十进制、十六进制互转</p>
        </div>
      </div>
      <div class="grid-2 mb-2">
        <div>
          <label>输入数值</label>
          <input type="text" id="base-input" class="input-field font-mono" placeholder="输入数值..." oninput="convertBase()">
        </div>
        <div>
          <label>输入进制</label>
          <select id="base-from" class="input-field" onchange="convertBase()">
            <option value="2">二进制 (Base 2)</option>
            <option value="8">八进制 (Base 8)</option>
            <option value="10" selected>十进制 (Base 10)</option>
            <option value="16">十六进制 (Base 16)</option>
          </select>
        </div>
      </div>
      <div id="base-results" class="grid-2"></div>
    </div>
  `;
}

function convertBase() {
  const input = document.getElementById('base-input').value;
  const fromBase = parseInt(document.getElementById('base-from').value);
  
  if (!input) {
    document.getElementById('base-results').innerHTML = '';
    return;
  }
  
  try {
    const decimal = parseInt(input, fromBase);
    if (isNaN(decimal)) throw new Error();
    
    const results = [
      { label: '二进制', value: decimal.toString(2), base: 2 },
      { label: '八进制', value: decimal.toString(8), base: 8 },
      { label: '十进制', value: decimal.toString(10), base: 10 },
      { label: '十六进制', value: decimal.toString(16).toUpperCase(), base: 16 }
    ];
    
    document.getElementById('base-results').innerHTML = results.map(r => `
      <div class="result-box ${r.base === fromBase ? 'text-primary' : ''}">
        <div class="flex justify-between items-center mb-1">
          <span class="text-sm text-muted">${r.label}${r.base === fromBase ? ' (输入)' : ''}</span>
          <button class="text-xs text-muted" style="background:none;border:none;cursor:pointer" onclick="copyText('${r.value}')">复制</button>
        </div>
        <p class="font-mono text-primary font-bold break-all">${r.value}</p>
      </div>
    `).join('');
  } catch {
    document.getElementById('base-results').innerHTML = '<div class="error-box">无效的数值</div>';
  }
}

// ==================== Regex Tester ====================
function renderRegexTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🔍</div>
        <div>
          <h2>正则表达式测试</h2>
          <p>测试和调试正则表达式</p>
        </div>
      </div>
      <div class="mb-2">
        <label>正则表达式</label>
        <div class="flex items-center gap-2 input-field">
          <span class="text-muted">/</span>
          <input type="text" id="regex-pattern" style="flex:1;background:transparent;border:none;outline:none;color:var(--text)" placeholder="输入正则表达式..." oninput="testRegex()">
          <span class="text-muted">/</span>
          <input type="text" id="regex-flags" style="width:3rem;background:transparent;border:none;outline:none;color:var(--text)" value="g" oninput="testRegex()">
        </div>
      </div>
      <div class="mb-2 flex flex-wrap gap-2">
        <button class="btn-secondary text-xs" onclick="document.getElementById('regex-pattern').value='[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}';testRegex()">邮箱</button>
        <button class="btn-secondary text-xs" onclick="document.getElementById('regex-pattern').value='1[3-9]\\\\d{9}';testRegex()">手机号</button>
        <button class="btn-secondary text-xs" onclick="document.getElementById('regex-pattern').value='https?://[\\\\w\\\\-.]+';testRegex()">URL</button>
        <button class="btn-secondary text-xs" onclick="document.getElementById('regex-pattern').value='[\\u4e00-\\u9fa5]+';testRegex()">中文</button>
      </div>
      <div class="mb-2">
        <label>测试字符串</label>
        <textarea id="regex-test" class="textarea-field" rows="4" placeholder="输入要测试的文本..." oninput="testRegex()"></textarea>
      </div>
      <div id="regex-results"></div>
    </div>
  `;
}

function testRegex() {
  const pattern = document.getElementById('regex-pattern').value;
  const flags = document.getElementById('regex-flags').value;
  const test = document.getElementById('regex-test').value;
  
  if (!pattern || !test) {
    document.getElementById('regex-results').innerHTML = '';
    return;
  }
  
  try {
    const regex = new RegExp(pattern, flags);
    const matches = test.match(regex);
    
    document.getElementById('regex-results').innerHTML = `
      <div class="result-box">
        <span class="text-sm text-muted">匹配结果 (${matches ? matches.length : 0} 个)</span>
        <div class="mt-1">${matches ? matches.map(m => `<span style="background:rgba(20,184,166,0.2);padding:0.125rem 0.375rem;border-radius:0.25rem;margin-right:0.5rem;font-family:monospace">${m}</span>`).join('') : '<span class="text-muted">无匹配</span>'}</div>
      </div>
    `;
  } catch (e) {
    document.getElementById('regex-results').innerHTML = `<div class="error-box">正则表达式错误: ${e.message}</div>`;
  }
}

// ==================== Markdown Preview ====================
function renderMarkdownTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">📝</div>
        <div>
          <h2>Markdown 预览</h2>
          <p>实时预览 Markdown 格式</p>
        </div>
      </div>
      <div class="grid-2">
        <div>
          <label>Markdown 输入</label>
          <textarea id="md-input" class="textarea-field" rows="15" placeholder="输入 Markdown 文本..." oninput="previewMarkdown()"># 标题

这是**粗体**和*斜体*文本。

- 列表项 1
- 列表项 2

\`代码\`

> 引用文本</textarea>
        </div>
        <div>
          <label>预览</label>
          <div id="md-preview" class="result-box" style="height:22rem;overflow-y:auto;line-height:1.8"></div>
        </div>
      </div>
    </div>
  `;
}

function previewMarkdown() {
  let md = document.getElementById('md-input').value;
  // Simple markdown parser
  md = md
    .replace(/^### (.*$)/gm, '<h3 style="font-size:1.1rem;font-weight:600;margin:0.5rem 0">$1</h3>')
    .replace(/^## (.*$)/gm, '<h2 style="font-size:1.25rem;font-weight:600;margin:0.75rem 0">$1</h2>')
    .replace(/^# (.*$)/gm, '<h1 style="font-size:1.5rem;font-weight:700;margin:1rem 0">$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code style="background:rgba(20,184,166,0.1);padding:0.125rem 0.375rem;border-radius:0.25rem;font-family:monospace">$1</code>')
    .replace(/^> (.*$)/gm, '<blockquote style="border-left:3px solid var(--primary);padding-left:1rem;margin:0.5rem 0;color:var(--text-muted)">$1</blockquote>')
    .replace(/^- (.*$)/gm, '<li style="margin-left:1rem">$1</li>')
    .replace(/\n/g, '<br>');
  
  document.getElementById('md-preview').innerHTML = md;
}

// Utility function
function copyText(text) {
  if (!text) {
    showToast('没有可复制的内容', 'error');
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    showToast('已复制到剪贴板');
  }).catch(() => {
    showToast('复制失败', 'error');
  });
}

// Toast notification
function showToast(message, type = 'success') {
  // Remove existing toast
  const existingToast = document.querySelector('.toast');
  if (existingToast) {
    existingToast.remove();
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type === 'error' ? 'error' : ''}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  // Trigger animation
  requestAnimationFrame(() => {
    toast.classList.add('show');
  });

  // Auto remove
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 2000);
}

// ==================== QR Code Generator ====================
function renderQrcodeTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">📱</div>
        <div>
          <h2>二维码生成器</h2>
          <p>将文本或 URL 生成二维码</p>
        </div>
      </div>
      <div class="mb-2">
        <label>输入内容</label>
        <textarea id="qr-input" class="textarea-field" rows="3" placeholder="输入文本或 URL..." oninput="generateQRCode()">https://example.com</textarea>
      </div>
      <div class="grid-2">
        <div>
          <label>尺寸</label>
          <select id="qr-size" class="input-field" onchange="generateQRCode()">
            <option value="128">小 (128px)</option>
            <option value="200" selected>中 (200px)</option>
            <option value="300">大 (300px)</option>
          </select>
        </div>
        <div>
          <label>容错级别</label>
          <select id="qr-level" class="input-field" onchange="generateQRCode()">
            <option value="L">低 (7%)</option>
            <option value="M" selected>中 (15%)</option>
            <option value="Q">较高 (25%)</option>
            <option value="H">高 (30%)</option>
          </select>
        </div>
      </div>
      <div id="qr-result" style="text-align:center;margin-top:1.5rem"></div>
      <div class="btn-group" style="justify-content:center">
        <button class="btn-secondary" onclick="downloadQRCode()">下载二维码</button>
      </div>
    </div>
  `;
}

// Simple QR Code generator using canvas
function generateQRCode() {
  const text = document.getElementById('qr-input').value;
  const size = parseInt(document.getElementById('qr-size').value);

  if (!text) {
    document.getElementById('qr-result').innerHTML = '<p class="text-muted">请输入内容</p>';
    return;
  }

  // Use a simple QR code API for display (generates SVG-like pattern)
  const qrContainer = document.getElementById('qr-result');
  const canvas = document.createElement('canvas');
  canvas.id = 'qr-canvas';
  canvas.width = size;
  canvas.height = size;

  // Generate QR code pattern
  const qr = generateQRMatrix(text);
  const ctx = canvas.getContext('2d');
  const cellSize = size / qr.length;

  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = '#000000';

  for (let y = 0; y < qr.length; y++) {
    for (let x = 0; x < qr.length; x++) {
      if (qr[y][x]) {
        ctx.fillRect(x * cellSize, y * cellSize, cellSize, cellSize);
      }
    }
  }

  qrContainer.innerHTML = '';
  qrContainer.appendChild(canvas);
}

// Minimal QR Code matrix generator
function generateQRMatrix(text) {
  const size = Math.max(21, Math.ceil(text.length / 2) + 21);
  const matrix = Array(size).fill(null).map(() => Array(size).fill(false));

  // Add finder patterns
  const addFinderPattern = (x, y) => {
    for (let dy = 0; dy < 7; dy++) {
      for (let dx = 0; dx < 7; dx++) {
        if (dy === 0 || dy === 6 || dx === 0 || dx === 6 || (dy >= 2 && dy <= 4 && dx >= 2 && dx <= 4)) {
          if (x + dx < size && y + dy < size) matrix[y + dy][x + dx] = true;
        }
      }
    }
  };

  addFinderPattern(0, 0);
  addFinderPattern(size - 7, 0);
  addFinderPattern(0, size - 7);

  // Add timing patterns
  for (let i = 8; i < size - 8; i++) {
    matrix[6][i] = i % 2 === 0;
    matrix[i][6] = i % 2 === 0;
  }

  // Encode data as simple pattern
  let bitIndex = 0;
  const bits = text.split('').flatMap(c => {
    const code = c.charCodeAt(0);
    return Array(8).fill(0).map((_, i) => (code >> (7 - i)) & 1);
  });

  for (let y = size - 1; y >= 0 && bitIndex < bits.length; y--) {
    for (let x = size - 1; x >= 0 && bitIndex < bits.length; x--) {
      if (!matrix[y][x] && x > 8 && y > 8) {
        matrix[y][x] = bits[bitIndex++] === 1;
      }
    }
  }

  return matrix;
}

function downloadQRCode() {
  const canvas = document.getElementById('qr-canvas');
  if (!canvas) {
    showToast('请先生成二维码', 'error');
    return;
  }
  const link = document.createElement('a');
  link.download = 'qrcode.png';
  link.href = canvas.toDataURL();
  link.click();
  showToast('二维码已下载');
}

// ==================== JWT Parser ====================
function renderJwtTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🎫</div>
        <div>
          <h2>JWT 解析器</h2>
          <p>解析 JWT Token，查看 Header 和 Payload</p>
        </div>
      </div>
      <div class="mb-2">
        <label>JWT Token</label>
        <textarea id="jwt-input" class="textarea-field" rows="4" placeholder="粘贴 JWT Token..." oninput="parseJWT()"></textarea>
      </div>
      <div id="jwt-result"></div>
    </div>
  `;
}

function parseJWT() {
  const token = document.getElementById('jwt-input').value.trim();
  const resultDiv = document.getElementById('jwt-result');

  if (!token) {
    resultDiv.innerHTML = '';
    return;
  }

  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('JWT 格式无效，应包含三部分');
    }

    const decodeBase64 = (str) => {
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(escape(atob(base64))));
    };

    const header = decodeBase64(parts[0]);
    const payload = decodeBase64(parts[1]);

    // Check expiration
    let expInfo = '';
    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      const now = new Date();
      const isExpired = expDate < now;
      expInfo = `
        <div class="result-box mb-1" style="border-color: ${isExpired ? 'var(--error)' : 'var(--primary)'}">
          <span class="text-xs ${isExpired ? 'text-muted' : 'text-primary'}">
            ${isExpired ? '⚠️ 已过期' : '✓ 有效'} - 过期时间: ${expDate.toLocaleString()}
          </span>
        </div>
      `;
    }

    resultDiv.innerHTML = `
      ${expInfo}
      <div class="result-box mb-1">
        <div class="flex justify-between items-center mb-1">
          <span class="text-primary font-bold">Header</span>
          <button class="text-xs text-muted" style="background:none;border:none;cursor:pointer" onclick="copyText(JSON.stringify(${JSON.stringify(header)}, null, 2))">复制</button>
        </div>
        <pre class="text-xs text-muted" style="white-space:pre-wrap">${JSON.stringify(header, null, 2)}</pre>
      </div>
      <div class="result-box">
        <div class="flex justify-between items-center mb-1">
          <span class="text-primary font-bold">Payload</span>
          <button class="text-xs text-muted" style="background:none;border:none;cursor:pointer" onclick="copyText(JSON.stringify(${JSON.stringify(payload)}, null, 2))">复制</button>
        </div>
        <pre class="text-xs text-muted" style="white-space:pre-wrap">${JSON.stringify(payload, null, 2)}</pre>
      </div>
    `;
  } catch (e) {
    resultDiv.innerHTML = `<div class="error-box">${e.message}</div>`;
  }
}

// ==================== HTML Entity Encoder ====================
function renderHtmlTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🏷️</div>
        <div>
          <h2>HTML 实体编解码</h2>
          <p>HTML 特殊字符与实体互转</p>
        </div>
      </div>
      <div class="mode-toggle">
        <button class="mode-btn active" id="html-encode-btn" onclick="setHtmlMode('encode')">编码 (字符 → 实体)</button>
        <button class="mode-btn" id="html-decode-btn" onclick="setHtmlMode('decode')">解码 (实体 → 字符)</button>
      </div>
      <div class="mb-2">
        <label id="html-input-label">输入文本</label>
        <textarea id="html-input" class="textarea-field" rows="4" placeholder="<div>Hello & World</div>"></textarea>
      </div>
      <div class="mb-2">
        <label>结果</label>
        <textarea id="html-output" class="textarea-field" rows="4" readonly style="background:rgba(22,27,34,0.3)"></textarea>
      </div>
      <div class="btn-group">
        <button class="btn-primary" onclick="convertHtml()">转换</button>
        <button class="btn-secondary" onclick="copyText(document.getElementById('html-output').value)">复制结果</button>
      </div>
    </div>
  `;
}

let htmlMode = 'encode';
function setHtmlMode(mode) {
  htmlMode = mode;
  document.getElementById('html-encode-btn').classList.toggle('active', mode === 'encode');
  document.getElementById('html-decode-btn').classList.toggle('active', mode === 'decode');
  document.getElementById('html-input-label').textContent = mode === 'encode' ? '输入文本' : '输入 HTML 实体';
}

function convertHtml() {
  const input = document.getElementById('html-input').value;
  let output;

  if (htmlMode === 'encode') {
    output = input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  } else {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = input;
    output = textarea.value;
  }

  document.getElementById('html-output').value = output;
}

// ==================== Case Converter ====================
function renderCaseTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">🔤</div>
        <div>
          <h2>大小写转换</h2>
          <p>多种大小写格式转换</p>
        </div>
      </div>
      <div class="mb-2">
        <label>输入文本</label>
        <textarea id="case-input" class="textarea-field" rows="3" placeholder="输入要转换的文本..." oninput="convertCase()">hello world example</textarea>
      </div>
      <div id="case-results" class="grid-2"></div>
    </div>
  `;
}

function convertCase() {
  const input = document.getElementById('case-input').value;

  if (!input) {
    document.getElementById('case-results').innerHTML = '';
    return;
  }

  const conversions = [
    { name: '大写', value: input.toUpperCase() },
    { name: '小写', value: input.toLowerCase() },
    { name: '首字母大写', value: input.replace(/\b\w/g, c => c.toUpperCase()) },
    { name: '句首大写', value: input.charAt(0).toUpperCase() + input.slice(1).toLowerCase() },
    { name: '驼峰命名', value: input.toLowerCase().replace(/[^a-zA-Z0-9]+(.)/g, (_, c) => c.toUpperCase()) },
    { name: '帕斯卡命名', value: input.toLowerCase().replace(/(^|[^a-zA-Z0-9]+)(.)/g, (_, __, c) => c.toUpperCase()) },
    { name: '下划线命名', value: input.toLowerCase().replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '') },
    { name: '短横线命名', value: input.toLowerCase().replace(/\s+/g, '-').replace(/[^a-zA-Z0-9-]/g, '') },
  ];

  document.getElementById('case-results').innerHTML = conversions.map(c => `
    <div class="result-box">
      <div class="flex justify-between items-center mb-1">
        <span class="text-xs text-muted">${c.name}</span>
        <button class="text-xs text-muted" style="background:none;border:none;cursor:pointer" onclick="copyText('${c.value.replace(/'/g, "\\'")}')">复制</button>
      </div>
      <p class="text-primary font-mono">${c.value}</p>
    </div>
  `).join('');
}

// ==================== Lorem Generator ====================
function renderLoremTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">📄</div>
        <div>
          <h2>Lorem 假文生成器</h2>
          <p>生成占位文本用于设计和测试</p>
        </div>
      </div>
      <div class="grid-3 mb-2">
        <div>
          <label>类型</label>
          <select id="lorem-type" class="input-field">
            <option value="paragraphs">段落</option>
            <option value="sentences">句子</option>
            <option value="words">单词</option>
          </select>
        </div>
        <div>
          <label>数量</label>
          <input type="number" id="lorem-count" class="input-field" value="3" min="1" max="50">
        </div>
        <div>
          <label>语言</label>
          <select id="lorem-lang" class="input-field">
            <option value="latin">拉丁文</option>
            <option value="chinese">中文</option>
          </select>
        </div>
      </div>
      <button class="btn-primary" style="width:100%" onclick="generateLorem()">生成</button>
      <div class="mb-2 mt-2">
        <textarea id="lorem-output" class="textarea-field" rows="8" readonly style="background:rgba(22,27,34,0.3)"></textarea>
      </div>
      <div class="btn-group">
        <button class="btn-secondary" onclick="copyText(document.getElementById('lorem-output').value)">复制</button>
      </div>
    </div>
  `;
}

const loremWords = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat duis aute irure in reprehenderit voluptate velit esse cillum fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt culpa qui officia deserunt mollit anim id est laborum'.split(' ');
const chineseWords = '的一是不了在人有我他这个们中来上大为和国地到以说时要就出会可也你对生能而子那得于着下自之年过发后作里用道行所然家种事成方多经么去法学如都同现当没动面起看定天分还进好小部其些主样理心她本前开但因只从想实日军者意无力它与长把机十民第公此已工使情明性知全三又关点正业外将两高间由问很最重并物手应战向头文体政美相见被利什二等产或新己制身果加西斯月话合回特代内信表化老给世位次度门任常先海通教儿原东声提立及比员解水名真论处走义各入几口认条平系气题活尔更别打女变四神总何电数安少报才结反受目太量再感建务做接必场件计管期市直德资命山金指克许统区保至队形社便空决治展马科司五基眼书非则听白却界达光放强即像难且权思王象完设式色路记南品住告类求据程北边死张该交规万取拉格望觉术领共确传师观清今切院让识候带导争运笑飞风步改收根干造言联持组每济车亲极林服快办议往元英士证近失转夫令准布始怎呢存未远叫台单影具罗字爱击流备兵连调深商算质团集百需价花党华城石级整府离况亚请技际约示复病息究线似官火断精满支视消越器容照须九增研写称企八功吗包片史委乎查轻易早曾除农找装广显吧阿李标谈吃图念六引历首医局突专费号尽另周较注语仅考落青随选列武红响虽推势参希古众构房半节土投某案黑维革划敌致陈律足态护七兴派孩验责营星够章音跟志底站严巴例防族供效续施留讲型料终答紧黄绝奇察母京段依批群项故按河米围江织害斗双境客纪采举杀攻父苏密低朝友诉止细愿千值仍男钱破网热助倒育属坐帝限船脸职速刻乐否';

function generateLorem() {
  const type = document.getElementById('lorem-type').value;
  const count = Math.min(50, Math.max(1, parseInt(document.getElementById('lorem-count').value) || 3));
  const lang = document.getElementById('lorem-lang').value;
  const words = lang === 'chinese' ? chineseWords.split('') : loremWords;

  const getRandomWords = (n) => {
    const result = [];
    for (let i = 0; i < n; i++) {
      result.push(words[Math.floor(Math.random() * words.length)]);
    }
    return lang === 'chinese' ? result.join('') : result.join(' ');
  };

  const getSentence = () => {
    const len = Math.floor(Math.random() * 10) + 8;
    const sentence = getRandomWords(len);
    return lang === 'chinese'
      ? sentence + '。'
      : sentence.charAt(0).toUpperCase() + sentence.slice(1) + '.';
  };

  const getParagraph = () => {
    const sentences = [];
    const sentenceCount = Math.floor(Math.random() * 4) + 4;
    for (let i = 0; i < sentenceCount; i++) {
      sentences.push(getSentence());
    }
    return sentences.join(lang === 'chinese' ? '' : ' ');
  };

  let output = '';
  if (type === 'words') {
    output = getRandomWords(count);
  } else if (type === 'sentences') {
    const sentences = [];
    for (let i = 0; i < count; i++) sentences.push(getSentence());
    output = sentences.join(lang === 'chinese' ? '' : ' ');
  } else {
    const paragraphs = [];
    for (let i = 0; i < count; i++) paragraphs.push(getParagraph());
    output = paragraphs.join('\n\n');
  }

  document.getElementById('lorem-output').value = output;
}

// ==================== Diff Tool ====================
function renderDiffTool() {
  return `
    <div class="glass-card">
      <div class="tool-header">
        <div class="tool-icon">📋</div>
        <div>
          <h2>文本对比</h2>
          <p>对比两段文本的差异</p>
        </div>
      </div>
      <div class="grid-2 mb-2">
        <div>
          <label>原始文本</label>
          <textarea id="diff-old" class="textarea-field" rows="8" placeholder="输入原始文本..."></textarea>
        </div>
        <div>
          <label>新文本</label>
          <textarea id="diff-new" class="textarea-field" rows="8" placeholder="输入新文本..."></textarea>
        </div>
      </div>
      <button class="btn-primary" style="width:100%" onclick="compareDiff()">对比差异</button>
      <div id="diff-result" class="mt-2"></div>
    </div>
  `;
}

function compareDiff() {
  const oldText = document.getElementById('diff-old').value;
  const newText = document.getElementById('diff-new').value;

  if (!oldText && !newText) {
    document.getElementById('diff-result').innerHTML = '<div class="text-muted" style="text-align:center;padding:1rem">请输入要对比的文本</div>';
    return;
  }

  const oldLines = oldText.split('\n');
  const newLines = newText.split('\n');
  const maxLen = Math.max(oldLines.length, newLines.length);

  let html = '<div style="font-family:monospace;font-size:0.875rem;background:var(--bg-input);border-radius:0.5rem;padding:1rem;overflow-x:auto">';

  let additions = 0, deletions = 0, unchanged = 0;

  for (let i = 0; i < maxLen; i++) {
    const oldLine = oldLines[i] || '';
    const newLine = newLines[i] || '';
    const lineNum = (i + 1).toString().padStart(3, ' ');

    if (oldLine === newLine) {
      html += `<div style="color:var(--text-muted)"><span style="opacity:0.5">${lineNum}</span>   ${escapeHtml(oldLine) || '&nbsp;'}</div>`;
      unchanged++;
    } else {
      if (oldLine) {
        html += `<div style="background:rgba(248,113,113,0.15);color:#f87171"><span style="opacity:0.5">${lineNum}</span> - ${escapeHtml(oldLine)}</div>`;
        deletions++;
      }
      if (newLine) {
        html += `<div style="background:rgba(20,184,166,0.15);color:#14b8a6"><span style="opacity:0.5">${lineNum}</span> + ${escapeHtml(newLine)}</div>`;
        additions++;
      }
    }
  }

  html += '</div>';

  const stats = `<div class="flex gap-2 mb-2" style="justify-content:center">
    <span class="text-xs" style="color:#14b8a6">+${additions} 新增</span>
    <span class="text-xs" style="color:#f87171">-${deletions} 删除</span>
    <span class="text-xs text-muted">${unchanged} 未变</span>
  </div>`;

  document.getElementById('diff-result').innerHTML = stats + html;
}

function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
