const express = require('express');
const path = require('path');
const https = require('https');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'templates')));

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';

// Free models in priority order — tries next if one fails
const FREE_MODELS = [
  'meta-llama/llama-3.1-8b-instruct:free',
  'mistralai/mistral-7b-instruct:free',
  'google/gemma-3-4b-it:free',
  'qwen/qwen2.5-7b-instruct:free'
];

function callOpenRouter(model, allMessages) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ model, messages: allMessages });

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
          if (parsed.error || res.statusCode !== 200) {
            reject({ status: res.statusCode, error: parsed.error });
          } else {
            resolve(parsed.choices?.[0]?.message?.content || '');
          }
        } catch (e) {
          reject({ status: 500, error: e.message });
        }
      });
    });

    req.on('error', (err) => reject({ status: 500, error: err.message }));
    req.write(payload);
    req.end();
  });
}

app.post('/api/chat', async (req, res) => {
  const { messages, system } = req.body;

  if (!OPENROUTER_API_KEY) {
    return res.status(500).json({ error: 'OPENROUTER_API_KEY not set on server.' });
  }

  const allMessages = [
    { role: 'system', content: system || 'You are AXIOM, a sleek, highly capable AI assistant with a slightly futuristic but friendly personality. Be concise, precise, and helpful.' },
    ...messages
  ];

  for (const model of FREE_MODELS) {
    try {
      console.log(`Trying model: ${model}`);
      const text = await callOpenRouter(model, allMessages);
      console.log(`Success with model: ${model}`);
      return res.json({ content: [{ text }] });
    } catch (err) {
      console.warn(`Model ${model} failed (${err.status}):`, err.error?.message || err.error);
      // Try next model
    }
  }

  res.status(500).json({ error: 'All models are currently unavailable. Please try again in a moment.' });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
