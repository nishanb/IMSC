const express = require('express');
const app = express();
const port = 3000;

// Insecure middleware for testing
app.use(express.json());

// Vulnerable route (for demonstration)
app.get('/', (req, res) => {
    res.json({ 
        message: 'Vulnerable Test Application',
        status: 'running',
        warning: 'This container contains deliberate vulnerabilities for testing'
    });
});

// Another vulnerable endpoint
app.get('/info', (req, res) => {
    res.json({
        environment: process.env,
        version: process.version,
        platform: process.platform
    });
});

app.listen(port, '0.0.0.0', () => {
    console.log(`🌐 Vulnerable test app listening at http://0.0.0.0:${port}`);
}); 