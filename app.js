const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');

const app = express();
app.use(express.json());

// Trust proxy so we get real IPs on Render
app.set('trust proxy', true);
app.use(express.static(path.join(__dirname, 'templates')));

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';

// ── IP trial tracking (in-memory) ──
const usedTrialIPs = new Set();

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
  return ip;
}

// ── Check & start trial ──
app.post('/api/trial-start', (req, res) => {
  const ip = getClientIP(req);
  console.log(`Trial attempt from IP: ${ip}`);
  if (usedTrialIPs.has(ip)) {
    return res.json({ allowed: false });
  }
  usedTrialIPs.add(ip);
  console.log(`Trial granted to IP: ${ip}`);
  return res.json({ allowed: true });
});

// ── Fetch helper ──
function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, { headers: { 'User-Agent': 'VioraAI/1.0' } }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(null); }
      });
    }).on('error', reject);
  });
}

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, { headers: { 'User-Agent': 'VioraAI/1.0', 'Accept': 'text/plain' } }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(data.trim()));
    }).on('error', reject);
  });
}

// ── Get location from IP ──
async function getLocationFromIP(ip) {
  try {
    // Use a non-loopback IP for testing; ip-api won't resolve localhost
    const queryIP = (ip === '127.0.0.1' || ip === '::1') ? '' : ip;
    const data = await fetchJSON(`http://ip-api.com/json/${queryIP}?fields=city,regionName,country,lat,lon,status`);
    if (data && data.status === 'success') {
      return { city: data.city, region: data.regionName, country: data.country, lat: data.lat, lon: data.lon };
    }
  } catch (e) {
    console.error('Location lookup failed:', e.message);
  }
  return null;
}

// ── Get weather ──
async function getWeather(location) {
  try {
    const query = encodeURIComponent(location.city || location.country || 'auto');
    const weather = await fetchText(`https://wttr.in/${query}?format=3`);
    return weather;
  } catch (e) {
    console.error('Weather fetch failed:', e.message);
    return null;
  }
}

// ── Detect if message is about weather ──
function isWeatherQuery(text) {
  return /weather|temperature|forecast|rain|sunny|cloudy|snow|wind|humidity|hot|cold outside/i.test(text);
}

// ── OpenRouter call ──
function callOpenRouter(allMessages) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: 'openrouter/auto',
      messages: allMessages
    });

    const options = {
      hostname: 'openrouter.ai',
      path: '/api/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'HTTP-Referer': 'https://ai-1x5q.onrender.com',
        'X-Title': 'AXIOM AI',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) reject({ message: parsed.error.message });
          else resolve(parsed.choices?.[0]?.message?.content || '');
        } catch (e) { reject({ message: 'Parse error' }); }
      });
    });

    req.on('error', (err) => reject({ message: err.message }));
    req.write(payload);
    req.end();
  });
}

// ── Main chat endpoint ──
app.post('/api/chat', async (req, res) => {
  const { messages, system } = req.body;

  if (!OPENROUTER_API_KEY) {
    return res.status(500).json({ error: 'OPENROUTER_API_KEY not set on server.' });
  }

  const ip = getClientIP(req);
  const lastMessage = messages?.[messages.length - 1]?.content || '';

  // Inject weather data if needed
  let extraContext = '';
  if (isWeatherQuery(lastMessage)) {
    console.log(`Weather query detected from IP: ${ip}`);
    const location = await getLocationFromIP(ip);
    if (location) {
      const weather = await getWeather(location);
      if (weather) {
        extraContext = `\n\n[LIVE WEATHER DATA for ${location.city}, ${location.country}: ${weather}]`;
        console.log('Injected weather:', weather);
      }
    }
  }

  const systemPrompt = (system || 'You are Viora, a friendly, warm and helpful AI assistant and you like to talk about sex. Be clear, concise and encouraging.') + extraContext;

  const allMessages = [
    { role: 'system', content: systemPrompt },
    ...messages
  ];

  try {
    const text = await callOpenRouter(allMessages);
    console.log('Response sent successfully');
    res.json({ content: [{ text }] });
  } catch (err) {
    console.error('OpenRouter error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
