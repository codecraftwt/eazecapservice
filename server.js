const express = require('express');
const cors = require('cors');
const { S3Client, GetObjectTaggingCommand } = require('@aws-sdk/client-s3');
require('dotenv').config()
const app = express();
app.use(cors()); // Allows your React app (localhost:8080) to call this API

// 1. Initialize S3 Client
// Ensure your environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) are set
// The backend is initialized with the keys SECURELY
const s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    }
});
const BUCKET_NAME = "eazecap-uploads-2026";

app.get('/api/check-scan-status', async (req, res) => {
    const fileKey = req.query.key; // The path to the file in S3

    if (!fileKey) {
        return res.status(400).json({ error: "File key is required" });
    }

    try {
        // 2. Request Tags from S3
        const command = new GetObjectTaggingCommand({
            Bucket: BUCKET_NAME,
            Key: fileKey,
        });

        const response = await s3Client.send(command);

        // 3. Look for the GuardDuty Malware Tag
        // Tag Key: GuardDutyMalwareScanStatus
        // Tag Values: NO_THREATS_FOUND, THREATS_FOUND, UNSUPPORTED, etc.
        const scanTag = response.TagSet.find(tag => tag.Key === 'GuardDutyMalwareScanStatus');

        if (!scanTag) {
            // If the tag isn't there yet, GuardDuty is still scanning
            return res.json({ status: "SCANNING" });
        }

        res.json({ 
            status: scanTag.Value, 
            isSafe: scanTag.Value === "NO_THREATS_FOUND" 
        });

    } catch (error) {
        console.error("S3 Tagging Error:", error);
        res.status(500).json({ error: "Failed to fetch scan status from AWS" });
    }
});

app.get('/', (req, res) => {
    res.send('Hello! The server is up and running.');
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Malware Check Server running on http://localhost:${PORT}`);
});