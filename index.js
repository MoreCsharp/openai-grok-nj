const express = require('express');
const session = require('express-session');
const fs = require('fs').promises;
const path = require('path');
const app = express();
app.set('view engine', 'ejs'); // 设置 EJS 为模板引擎

app.use(session({
    secret: '123456789741852963', // 重要：改成你自己的强密钥！
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false   // 如果你的网站使用 HTTPS，取消注释这一行
    }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const CONFIG_FILE = path.join(__dirname, 'config.json');

// 读取或创建配置文件
async function loadConfig() {
    try {
        const data = await fs.readFile(CONFIG_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            // 首次运行，从环境变量创建配置
            initialConfig = { 
              cookies: [],
              last_cookie_index: { "grok-2": 0, "grok-3": 0, "grok-3-thinking": 0 },
              temporary_mode: true
            };
            await saveConfig(initialConfig);
            return initialConfig;

        } else {
            console.error("读取配置文件时出错:", error);
            throw error;
        }
    }
}

// 保存配置文件
async function saveConfig(config) {
    try {
        await fs.writeFile(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
    } catch (error) {
        console.error("保存配置文件时出错:", error);
        throw error;
    }
}

// requireAuth 中间件
async function requireAuth(req, res, next) {
    if (req.baseUrl.startsWith("/config")) {
        if (req.session.loggedIn || !process.env.PASSWORD) {
            return next();
        } else {
            return res.redirect('/config/login');
        }
    } else {
        const auth = req.headers.authorization;
        if (auth && auth.startsWith('Bearer ')) {
            const token = auth.split(' ')[1];
            if (!process.env.PASSWORD || (process.env.PASSWORD && token === process.env.PASSWORD)) {
                return next();
            } else {
                return res.status(401).json({ error: "无效的 API 密钥" });
            }
        } else {
            return res.status(401).json({ error: "缺少或无效的 Authorization 标头" });
        }
    }
}

function loginPage(req, res) {
    res.render('login', { error: null }); // 渲染 views/login.ejs 模板
}

async function handleLogin(req, res) {
    const { password } = req.body;
    if (!process.env.PASSWORD) {
        req.session.loggedIn = true;
        return res.redirect('/config');
    }

    if (process.env.PASSWORD == password) {
        req.session.loggedIn = true;
        return res.redirect('/config');
    } else {
        return res.render('login', { error: '密码错误' });
    }
}

function truncateCookie(cookie) {
    return cookie.length > 50 ? cookie.substring(0, 50) + "..." : cookie;
}

function getCommonHeaders(cookie) {
    return {
        "Accept": "*/*",
        "Content-Type": "application/json",
        "Origin": "https://grok.com",
        "Referer": "https://grok.com/",
        "Cookie": cookie,
        "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)],
    };
}

async function fetchWithTimeout(url, options, timeout = 5000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, {options, signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error('请求超时');
        }
        throw error;
    }
}

/**
 * 使用指定 cookie 调用 CHECK_URL 接口，返回 JSON 数据（带超时保护）
 */
async function checkRateLimitWithCookie(model, cookie, isReasoning) {
    const headers = getCommonHeaders(cookie);
    const payload = {
        requestKind: isReasoning ? "REASONING" : "DEFAULT",
        modelName: model,
    };
    const response = await fetchWithTimeout(CHECK_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
    });
    if (!response.ok) {
        throw new Error(`Rate limit check failed for model ${model}, status: ${response.status}`);
    }
    return await response.json();
}

/**
 * 检查单个 cookie 的状态：
 */
async function checkCookieStatus(cookie) {
    let rateLimitDetails = [];

    try {
        // 先测试 grok-2
        const dataGrok2 = await checkRateLimitWithCookie("grok-2", cookie, false);
        rateLimitDetails.push({ model: "grok-2", remainingQueries: dataGrok2.remainingQueries });
    } catch (e) {
        return { expired: true, rateLimited: false, rateLimitDetails: [] };
    }

    // 再检查 grok-3
    try {
        const dataGrok3 = await checkRateLimitWithCookie("grok-3", cookie, false);
        rateLimitDetails.push({ model: "grok-3", remainingQueries: dataGrok3.remainingQueries });
    } catch (e) {
        rateLimitDetails.push({ model: "grok-3", error: e.toString(), remainingQueries: 0 });
    }

    const rateLimited = rateLimitDetails.every(detail => detail.remainingQueries === 0);
    return { expired: false, rateLimited, rateLimitDetails };
}

async function configPage(req, res) {
    const config = await loadConfig();
    let cookieStatuses = [];

    try {
        cookieStatuses = await Promise.all(
            config.cookies.map(cookie =>
                checkCookieStatus(cookie).catch(e => ({ expired: true, rateLimited: false, rateLimitDetails: [] }))
            )
        );
    } catch (e) {
        console.error("Error checking cookie statuses:", e);
        // 在实际应用中，你可能需要更优雅地处理错误，例如显示错误消息给用户
        cookieStatuses = config.cookies.map(() => ({ expired: true, rateLimited: false, rateLimitDetails: [] }));
    }

    // 将数据传递给 EJS 模板
    res.render('config', {
        cookies: config.cookies,
        cookieStatuses: cookieStatuses,
        truncateCookie: truncateCookie, // 将 truncateCookie 函数传递给模板
        temporary_mode: config.temporary_mode, // 假设默认为 false
    });
}

async function updateConfig(req, res) {
    const { action, cookie, index, password } = req.body;
    const config = await loadConfig();

    if (action === 'add') {
        if (cookie && cookie.trim() !== '') {
            config.cookies.push(cookie.trim());
        }
    } else if (action === 'delete') {
        config.cookies = [];
    } else if (action === 'delete_one') {
        const i = parseInt(index, 10);
        if (!isNaN(i) && i >= 0 && i < config.cookies.length) {
            config.cookies.splice(i, 1);
        }
    } else if (action === 'update_password') {
        if (password) {
            const saltRounds = 10;
            const hash = await bcrypt.hash(password, saltRounds);
            config.passwordHash = hash;
        } else {
            delete config.passwordHash;
        }
    } else if (action === 'toggle') {
        // 切换 temporary_mode
        config.temporary_mode = !config.temporary_mode;
    }

    await saveConfig(config);
    res.redirect('/config');
}

async function handleModels(req, res) {
    const data = MODELS.map((model) => ({
      id: model,
      object: "model",
      created: Math.floor(Date.now() / 1000),
      owned_by: "Elbert", // 你可以根据需要更改这个值
      name: model,
    }));
  
    res.json({ object: "list", data });
  }

/* ========== 消息预处理 ========== */
function magic(messages) {
    let disableSearch = false;
    let forceConcise = false;
    if (messages && messages.length > 0) {
      let first = messages[0].content;
      if (first.includes("<|disableSearch|>")) {
        disableSearch = true;
        first = first.replace(/<\|disableSearch\|>/g, "");
      }
      if (first.includes("<|forceConcise|>")) {
        forceConcise = true;
        first = first.replace(/<\|forceConcise\|>/g, "");
      }
      messages[0].content = first;
    }
    return { disableSearch, forceConcise, messages };
}

function formatMessage(messages) {
  let roleMap = { user: "Human", assistant: "Assistant", system: "System" };
  const roleInfoPattern = /<roleInfo>\s*user:\s*([^\n]*)\s*assistant:\s*([^\n]*)\s*system:\s*([^\n]*)\s*prefix:\s*([^\n]*)\s*<\/roleInfo>\n/;
  let prefix = false;
  let firstContent = messages[0].content;
  let match = firstContent.match(roleInfoPattern);
  if (match) {
    roleMap = {
      user: match[1],
      assistant: match[2],
      system: match[3],
    };
    prefix = match[4] === "1";
    messages[0].content = firstContent.replace(roleInfoPattern, "");
  }
  let formatted = "";
  for (const msg of messages) {
    let role = prefix ? "\b" + roleMap[msg.role] : roleMap[msg.role];
    formatted += `${role}: ${msg.content}\n`;
  }
  return formatted;
}

  async function getNextAccount(model) {
    let config = await loadConfig();
    if (!config.cookies || config.cookies.length === 0) {
      throw new Error("没有可用的 cookie，请先通过配置页面添加。");
    }
    const num = config.cookies.length;
    const current = ((config.last_cookie_index[model] || 0) + 1) % num;
    config.last_cookie_index[model] = current;
  
    await saveConfig(config);
    return config.cookies[current];
}

async function handleRateLimits(req, res) {
    try {
      const reqJson = req.body; // 在 Express 中使用 req.body 获取 JSON 数据
      const model = reqJson.model;
      const isReasoning = !!reqJson.isReasoning;
      
      if (!MODELS.includes(model)) {
        return res.status(500).json({ error: "模型不可用" });
      }
      
      const result = await checkRateLimit(model, isReasoning);
      return res.json(result);
  
    } catch (e) {
      console.error("检查调用频率出错:", e);
      return res.status(500).json({ error: e.toString() });
    }
}

async function checkRateLimit(model, isReasoning) {
    let cookie;
    try {
      cookie = await getNextAccount(model);
    } catch (e) {
      console.error("获取账户时出错:", e);
      return { error: e.toString(), status: 500 };
    }
  
    const headers = getCommonHeaders(cookie);
    const payload = {
      requestKind: isReasoning ? "REASONING" : "DEFAULT",
      modelName: model,
    };
  
    try {
      const response = await fetchWithTimeout(CHECK_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
  
      if (!response.ok) {
        throw new Error("调用频率检查失败");
      }
  
      const data = await response.json();
      return data; // 返回 data 以便在 Express 处理程序中使用
  
    } catch (e) {
      console.error("调用频率检查异常:", e);
      return { error: e.toString(), status: 500 };
    }
}

//访问
async function handleChatCompletions(req, res) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: "缺少或无效的授权头部" });
    }
    const token = authHeader.split(' ')[1];
    if (token !== process.env.PASSWORD) {
      return res.status(401).json({ error: "无效的API密钥" });
    }
    try {
      const { stream, messages, model } = req.body;
      if (!MODELS.includes(model)) {
        return res.status(500).json({ error: "模型不可用" });
      }
      if (!messages) {
        return res.status(400).json({ error: "必须提供消息" });
      }
      const { disableSearch, forceConcise, messages: newMessages } = magic(messages);
      const formattedMessage = formatMessage(newMessages);
      const isReasoning = model.length > 6;
      const modelShortened = model.substring(0, 6);
      if (stream) {
        return await sendMessageStream(formattedMessage, modelShortened, disableSearch, forceConcise, isReasoning, res);
      } else {
        return await sendMessageNonStream(formattedMessage, modelShortened, disableSearch, forceConcise, isReasoning, res);
      }
    } catch (e) {
      console.error("处理chat completions时出错:", e);
      return res.status(500).json({ error: e.toString() });
    }
}

// Stream和非Stream消息发送的实现
async function sendMessageStream(message, model, disableSearch, forceConcise, isReasoning, res) {
    let cookie;
    try {
      cookie = await getNextAccount(model);
    } catch (e) {
      return res.status(500).json({ error: e.toString() });
    }
  
    const headers = getCommonHeaders(cookie);
    const config = await loadConfig();
    const payload = {
      temporary: config.temporary_mode,
      modelName: model,
      message,
      fileAttachments: [],
      imageAttachments: [],
      disableSearch,
      enableImageGeneration: false,
      returnImageBytes: false,
      returnRawGrokInXaiRequest: false,
      enableImageStreaming: true,
      imageGenerationCount: 2,
      forceConcise,
      toolOverrides: {},
      enableSideBySide: true,
      isPreset: false,
      sendFinalMetadata: true,
      customInstructions: "",
      deepsearchPreset: "",
      isReasoning
    };
    const init = {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    };
  
    try {
      const response = await fetchWithTimeout(TARGET_URL, init);
      if (!response.ok) {
        return res.status(500).json({ error: "发送消息失败" });
      }
  
      // 使用Node.js的流来处理
      const reader = response.body.getReader();
      res.setHeader('Content-Type', 'text/event-stream');
  
      let buffer = '';
      let thinking = 2;
  
      async function pushStreamData() {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
  
          buffer += new TextDecoder().decode(value, { stream: true });
          const lines = buffer.split("\n").filter(line => line.trim() !== "");
          buffer = lines.pop();
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            try {
              const data = JSON.parse(trimmed);
              if (!data?.result?.response || typeof data.result.response.token !== "string") {
                continue;
              }
              let token = data.result.response.token;
              let content = token;
              if (isReasoning) {
                if (thinking === 2) {
                  thinking = 1;
                  content = `<Thinking>\n${token}`;
                } else if (thinking === 1 && !data.result.response.isThinking) {
                  thinking = 0;
                  content = `\n</Thinking>\n${token}`;
                }
              }
              const chunkData = {
                id: "chatcmpl-" + crypto.randomUUID(),
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model,
                choices: [
                  { index: 0, delta: { content: content }, finish_reason: null },
                ],
              };
  
              // 向客户端发送数据
              res.write("data: " + JSON.stringify(chunkData) + "\n\n");
              if (data.result.response.isSoftStop) {
                const finalChunk = {
                  id: "chatcmpl-" + crypto.randomUUID(),
                  object: "chat.completion.chunk",
                  created: Math.floor(Date.now() / 1000),
                  model,
                  choices: [
                    { index: 0, delta: { content: content }, finish_reason: "completed" },
                  ],
                };
                res.write("data: " + JSON.stringify(finalChunk) + "\n\n");
                res.end();
                return;
              }
            } catch (e) {
              console.error("JSON 解析错误:", e, "行内容:", trimmed);
            }
          }
        }
      }
  
      pushStreamData();
    } catch (e) {
      console.error("处理sendMessageStream时出错:", e);
      res.status(500).json({ error: "流错误" });
    }
}
  
  async function sendMessageNonStream(message, model, disableSearch, forceConcise, isReasoning, res) {
    let cookie;
    try {
      cookie = await getNextAccount(model);
    } catch (e) {
      return res.status(500).json({ error: e.toString() });
    }
  
    const headers = getCommonHeaders(cookie);
    const config = await loadConfig();
    const payload = {
      temporary: config.temporary_mode,
      modelName: model,
      message,
      fileAttachments: [],
      imageAttachments: [],
      disableSearch,
      enableImageGeneration: false,
      returnImageBytes: false,
      returnRawGrokInXaiRequest: false,
      enableImageStreaming: true,
      imageGenerationCount: 2,
      forceConcise,
      toolOverrides: {},
      enableSideBySide: true,
      isPreset: false,
      sendFinalMetadata: true,
      customInstructions: "",
      deepsearchPreset: "",
      isReasoning
    };
    const init = {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    };
  
    try {
      const response = await fetchWithTimeout(TARGET_URL, init);
      if (!response.ok) {
        return res.status(500).json({ error: "发送消息失败" });
      }
  
      const fullText = await response.text();
      let finalMessage = '';
      const lines = fullText.split("\n").filter(line => line.trim() !== "");
      for (const line of lines) {
        try {
          const data = JSON.parse(line);
          if (data?.result?.response) {
            if (data.result.response.modelResponse && data.result.response.modelResponse.message) {
              finalMessage = data.result.response.modelResponse.message;
              break;
            } else if (typeof data.result.response.token === "string") {
              finalMessage += data.result.response.token;
            }
          }
        } catch (e) {
          console.error("JSON 解析错误:", e, "行内容:", line);
        }
      }
  
      const openai_response = {
        id: "chatcmpl-" + crypto.randomUUID(),
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model,
        choices: [
          { index: 0, message: { role: "assistant", content: finalMessage }, finish_reason: "completed" },
        ],
      };
      res.json(openai_response);
    } catch (e) {
      console.error("处理sendMessageNonStream时出错:", e);
      res.status(500).json({ error: "非流错误" });
    }
  }

// 路由
app.get('/', (req, res) => {
  res.redirect('/config'); // 重定向到 /config
});

app.use('/config', express.Router()
  .get('/login', loginPage)
  .post('/login', handleLogin)
  .use(requireAuth) // 对 /config 下的其他路由进行认证
  .get('/', configPage)
  .post('/', updateConfig));
  
app.get('/v1/models', handleModels);
app.get('/v1/rate-limits', handleRateLimits); // 新增的路由
app.post('/v1/chat/completions', handleChatCompletions); // 新增的路由


// 404 处理
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// 5. 启动服务器
const port = process.env.PORT || 3000; // 使用环境变量 PORT 或默认端口 3000
process.env.PASSWORD = "123456";
const MODELS = ["grok-2", "grok-3", "grok-3-thinking"];
const TARGET_URL = "https://grok.com/rest/app-chat/conversations/new";
const CHECK_URL = "https://grok.com/rest/rate-limits";
const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux i686; rv:124.0) Gecko/20100101 Firefox/124.0",
  ];
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});