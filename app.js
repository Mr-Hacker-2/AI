const express = require('express');
const path = require('path');
const app = express();

app.use(express.static(path.join(__dirname, 'templates')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
```

**Your repo structure should look like this:**
```
AI/
├── package.json      ← new
├── app.js            ← new
└── templates/
    └── index.html    ← your chatbot HTML (rename ai-chatbot.html to index.html)
