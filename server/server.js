const path = require('path');
const fs = require('fs');
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const winston = require('winston');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const connectDB = require('./config/db');
const documentRoutes = require('./routes/documentRoutes');
const authRoutes = require('./routes/authRoutes');
const auditRoutes = require('./routes/auditRoutes');
const folderRoutes = require('./routes/folderRoutes');
const app = express();

app.set('trust proxy', 1);

connectDB();

app.use(helmet({
  contentSecurityPolicy: false,
}));

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests from this IP, please try again later.' }
});
app.use('/api', limiter);

app.use(cors({
  origin: [process.env.CLIENT_URL,
    'http://localhost:5173',
    'https://vault.pinch.site'
  ],
  credentials: true
}));


app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use((req, res, next) => {
  if (req.body) req.body = mongoSanitize.sanitize(req.body);
  if (req.params) req.params = mongoSanitize.sanitize(req.params);
  next();
});
app.use(hpp());

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ],
});

app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/folders', folderRoutes);


const distPath = path.join(__dirname, '../client/dist');

console.log(`Configuring frontend from: ${distPath}`);

app.use(express.static(distPath));
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ message: 'API Endpoint Not Found' });
  }
  const indexPath = path.join(distPath, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    console.error(`Frontend build missing at ${indexPath}`);
    res.status(500).send('Server Error: Frontend build not found. Please check deployment logs.');
  }
});

mongoose.connection.once('open', async () => {
  try {
    console.log("Attempting to drop old aadhaarId index...");
    await mongoose.connection.collection('users').dropIndex('aadhaarId_1');
    console.log("✅ SUCCESS: Old 'aadhaarId_1' index dropped. Mongoose will recreate it correctly as sparse.");
  } catch (error) {
    console.log("ℹ️ Index drop skipped (Index not found or already fixed):", error.message);
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  logger.info(`[Server] Running on port ${PORT}`);
  logger.info(`[Server] Environment: ${process.env.NODE_ENV || 'undefined'}`);
});