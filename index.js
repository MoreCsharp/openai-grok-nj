const express = require('express');
const session = require('express-session');
const fs = require('fs').promises;
const path = require('path');
const app = express();
app.set('view engine', 'ejs'); // 设置 EJS 为模板引擎

app.use(session({
    secret: '123456789741852963', // 重要：改成你自己的强密钥！
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,   // 如果你的网站使用 HTTPS，取消注释这一行
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24
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
            initialConfig = { cookies: [], temporary_mode: true };
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
    const config = await loadConfig();
    if (req.baseUrl.startsWith("/config")) {
        if (req.session.loggedIn || !process.env.PASSWORD) {
            next();
        } else {
            res.redirect('/config/login');
        }
    } else {
        const auth = req.headers.authorization;
        if (auth && auth.startsWith('Bearer ')) {
            const token = auth.split(' ')[1];
            // 如果没有设置密码，或者提供了有效的令牌，则允许 API 访问
            if (!process.env.PASSWORD || (process.env.PASSWORD && await token == process.env.PASSWORD)) {
                next();
            } else {
                res.status(401).json({ error: "无效的 API 密钥" });
            }
        } else {
                res.status(401).json({ error: "缺少或无效的 Authorization 标头" });
            }
        }
}

function loginPage(req, res) {
    res.render('login', { error: null }); // 渲染 views/login.ejs 模板
}

async function handleLogin(req, res) {
    const { password } = req.body; // 获取密码, 可能为空
    const config = await loadConfig();

    // 如果没有设置密码，则直接允许登录 (不需要检查密码)
    if (!process.env.PASSWORD) {
        req.session.loggedIn = true;
        res.redirect('/config');
        return; // 提前返回，避免执行下面的密码检查
    }

    // 如果设置了密码，则进行密码验证
    if (process.env.PASSWORD && process.env.PASSWORD == password) {
        req.session.loggedIn = true;
        res.redirect('/config');
    } else {
        // 密码错误，或者提供了密码但没有设置密码
        res.render('login', { error: '密码错误' });
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
        console.log(typeof fetch);
        console.log(typeof path);
        const response = await fetch(url, { ...options, signal: controller.signal });
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

//假设的
function handleRateLimits(req,res){
    res.send('handleRateLimits')
}

function handleChatCompletions(req,res){
    res.send('handleChatCompletions')
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
const MODELS = ["grok-2", "grok-3", "grok-3-thinking"];
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