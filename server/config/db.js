const mongoose = require('mongoose');
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'database' },
    transports: [
        new winston.transports.File({ filename: 'logs/database.log' }),
        new winston.transports.Console({ format: winston.format.simple() }) 
    ],
});

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI, {
            serverSelectionTimeoutMS: 5000, 
            socketTimeoutMS: 45000, 
        });
        
        logger.info(`MongoDB Connected: ${conn.connection.host}`);

        mongoose.connection.on('error', (err) => {
            logger.error(`MongoDB Connection Error: ${err}`);
        });

        mongoose.connection.on('disconnected', () => {
            logger.warn('MongoDB Disconnected. Attempting to reconnect...');
        });

        mongoose.connection.on('reconnected', () => {
            logger.info('MongoDB Reconnected!');
        });

    } catch (error) {
        logger.error(`Initial Connection Failed: ${error.message}`);
    }
};

module.exports = connectDB;