/**
 * Environment variables validator & loader.
 *
 * Ensures all required environment variables are present on startup
 * to prevent silent runtime failures.
 */
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(import.meta.dirname, '../../.env') });

const requiredVars = [
  'PORT',
  'MONGODB_URI',
  'JWT_SECRET',
  'AGENT_TOKEN_SECRET',
];

for (const envVar of requiredVars) {
  if (!process.env[envVar]) {
    console.error(`[FATAL ERROR] Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '5000', 10),
  mongoUri: process.env.MONGODB_URI,
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
  agentTokenSecret: process.env.AGENT_TOKEN_SECRET,
  aiProvider: process.env.AI_PROVIDER || 'ollama',
  ollamaBaseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
  ollamaModel: process.env.OLLAMA_MODEL || 'llama3',
  openaiApiKey: process.env.OPENAI_API_KEY || '',
  openaiModel: process.env.OPENAI_MODEL || 'gpt-4o',
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY || '',
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  slackWebhookUrl: process.env.SLACK_WEBHOOK_URL || '',
  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || '',
};
